use std::collections::BTreeSet;
use std::path::Path;

use database_memory_core::graph_store::{GraphNodeRecord, GraphStore};
use database_memory_core::{
    capability_warnings, ColumnObject, ConstraintKind, ConstraintObject, IndexObject, ObjectKey,
};
use serde_json::json;

use crate::args::OutputFormat;

pub(crate) fn open_existing_store(cache_path: &Path) -> Result<GraphStore, String> {
    if !cache_path.exists() {
        return Err(format!(
            "cache path '{}' not found; run index first",
            cache_path.display()
        ));
    }
    GraphStore::open(cache_path).map_err(|err| err.to_string())
}

pub(crate) fn snapshot_key(alias: &str) -> String {
    if alias.contains(':') {
        alias.to_owned()
    } else {
        format!("sqlite:{alias}")
    }
}

pub(crate) fn require_snapshot(store: &GraphStore, snapshot_key: &str) -> Result<(), String> {
    store
        .get_snapshot(snapshot_key)
        .map_err(|err| err.to_string())?
        .map(|_| ())
        .ok_or_else(|| format!("snapshot '{snapshot_key}' not found in cache; run index first"))
}

fn snapshot_capability_warnings(
    store: &GraphStore,
    snapshot_key: &str,
) -> Result<Vec<String>, String> {
    store
        .get_snapshot_capabilities(snapshot_key)
        .map_err(|err| err.to_string())?
        .map(|capabilities| capability_warnings(&capabilities))
        .ok_or_else(|| format!("snapshot '{snapshot_key}' not found in cache; run index first"))
}

pub(crate) struct TableDescription {
    table_name: String,
    columns: Vec<ColumnObject>,
    primary_key: Vec<String>,
    outbound_foreign_keys: Vec<ForeignKeyDescription>,
    inbound_foreign_keys: Vec<ForeignKeyDescription>,
    indexes: Vec<IndexObject>,
    capability_warnings: Vec<String>,
}

struct ForeignKeyDescription {
    name: String,
    table: String,
    columns: Vec<String>,
    referenced_table: String,
    referenced_columns: Vec<String>,
}

pub(crate) fn describe_table(
    store: &GraphStore,
    snapshot_key: &str,
    table_name: &str,
) -> Result<TableDescription, String> {
    let table = find_table_node(store, snapshot_key, table_name)?;
    let columns = table_columns(store, snapshot_key, &table.node_key)?;
    let constraints = table_constraints(store, snapshot_key, &table.node_key)?;
    let primary_key = constraints
        .iter()
        .find(|constraint| constraint.kind == ConstraintKind::PrimaryKey)
        .map(|constraint| names_from_keys(&constraint.columns))
        .unwrap_or_default();
    let mut outbound_foreign_keys = constraints
        .iter()
        .filter(|constraint| constraint.kind == ConstraintKind::ForeignKey)
        .map(foreign_key_description)
        .collect::<Vec<_>>();
    outbound_foreign_keys.sort_by(|left, right| left.name.cmp(&right.name));

    let mut inbound_keys = BTreeSet::new();
    for column in &columns {
        for edge in store
            .edges_to(snapshot_key, &column.key.to_string())
            .map_err(|err| err.to_string())?
        {
            if edge.edge_type == "FK_TO_COLUMN" {
                inbound_keys.insert(edge.edge_from);
            }
        }
    }
    let mut inbound_foreign_keys = Vec::new();
    for key in inbound_keys {
        let node = required_node(store, snapshot_key, &key)?;
        inbound_foreign_keys.push(foreign_key_description(&foreign_key_from_node(&node)?));
    }
    inbound_foreign_keys.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(TableDescription {
        table_name: table_name.to_owned(),
        columns,
        primary_key,
        outbound_foreign_keys,
        inbound_foreign_keys,
        indexes: table_indexes(store, snapshot_key, &table.node_key)?,
        capability_warnings: snapshot_capability_warnings(store, snapshot_key)?,
    })
}

fn find_table_node(
    store: &GraphStore,
    snapshot_key: &str,
    table_name: &str,
) -> Result<GraphNodeRecord, String> {
    for node in store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
    {
        if object_key(&node)?.object_name == table_name {
            return Ok(node);
        }
    }
    Err(format!(
        "table '{table_name}' not found in snapshot '{snapshot_key}'"
    ))
}

fn table_columns(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
) -> Result<Vec<ColumnObject>, String> {
    let mut columns = Vec::new();
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|err| err.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_COLUMN" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            columns.push(column_from_node(&node)?);
        }
    }
    columns.sort_by_key(|column| column.ordinal_position);
    Ok(columns)
}

fn table_constraints(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
) -> Result<Vec<ConstraintObject>, String> {
    let mut constraints = Vec::new();
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|err| err.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_CONSTRAINT" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            constraints.push(constraint_from_node(&node)?);
        }
    }
    Ok(constraints)
}

fn table_indexes(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
) -> Result<Vec<IndexObject>, String> {
    let mut indexes = Vec::new();
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|err| err.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_INDEX" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            indexes.push(index_from_node(&node)?);
        }
    }
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(indexes)
}

pub(crate) fn render_table_description(
    description: &TableDescription,
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Text => render_table_description_text(description),
        OutputFormat::Json => render_table_description_json(description),
    }
}

fn render_table_description_text(description: &TableDescription) -> String {
    let mut out = format!(
        "table: {}
",
        description.table_name
    );
    out.push_str(
        "columns:
",
    );
    for column in &description.columns {
        out.push_str(&format!(
            "  {} {} nullable: {}
",
            column.name,
            column.data_type,
            yes_no(column.is_nullable)
        ));
    }
    out.push_str(&format!(
        "primary key: {}
",
        list_or_none(&description.primary_key)
    ));
    out.push_str(
        "foreign keys:
  outbound:
",
    );
    push_foreign_keys(&mut out, &description.outbound_foreign_keys);
    out.push_str(
        "  inbound:
",
    );
    push_foreign_keys(&mut out, &description.inbound_foreign_keys);
    out.push_str(
        "indexes:
",
    );
    if description.indexes.is_empty() {
        out.push_str(
            "  (none)
",
        );
    } else {
        for index in &description.indexes {
            out.push_str(&format!(
                "  {}: {} unique: {} primary: {}
",
                index.name,
                list_or_none(&names_from_keys(&index.columns)),
                yes_no(index.is_unique),
                yes_no(index.is_primary)
            ));
        }
    }
    if !description.capability_warnings.is_empty() {
        out.push_str(
            "capability warnings:
",
        );
        for warning in &description.capability_warnings {
            out.push_str(&format!(
                "  {warning}
"
            ));
        }
    }
    out
}

fn push_foreign_keys(out: &mut String, foreign_keys: &[ForeignKeyDescription]) {
    if foreign_keys.is_empty() {
        out.push_str(
            "    (none)
",
        );
    } else {
        for fk in foreign_keys {
            out.push_str(&format!(
                "    {}: {}({}) -> {}({})
",
                fk.name,
                fk.table,
                list_or_none(&fk.columns),
                fk.referenced_table,
                list_or_none(&fk.referenced_columns)
            ));
        }
    }
}

fn render_table_description_json(description: &TableDescription) -> String {
    let value = json!({
        "table": &description.table_name,
        "columns": description.columns.iter().map(|column| json!({
            "name": &column.name,
            "type": &column.data_type,
            "nullable": column.is_nullable,
        })).collect::<Vec<_>>(),
        "primary_key": &description.primary_key,
        "foreign_keys": {
            "outbound": foreign_keys_json(&description.outbound_foreign_keys),
            "inbound": foreign_keys_json(&description.inbound_foreign_keys),
        },
        "indexes": description.indexes.iter().map(|index| json!({
            "name": &index.name,
            "columns": names_from_keys(&index.columns),
            "unique": index.is_unique,
            "primary": index.is_primary,
        })).collect::<Vec<_>>(),
        "capability_warnings": &description.capability_warnings,
    });
    format!(
        "{}
",
        serde_json::to_string_pretty(&value).unwrap()
    )
}

fn foreign_keys_json(foreign_keys: &[ForeignKeyDescription]) -> Vec<serde_json::Value> {
    foreign_keys
        .iter()
        .map(|fk| {
            json!({
                "name": &fk.name,
                "table": &fk.table,
                "columns": &fk.columns,
                "referenced_table": &fk.referenced_table,
                "referenced_columns": &fk.referenced_columns,
            })
        })
        .collect()
}

pub(crate) fn render_find_table(
    store: &GraphStore,
    snapshot_key: &str,
    query: &str,
) -> Result<String, String> {
    let needle = query.to_lowercase();
    let mut out = String::new();
    for node in store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
    {
        let key = object_key(&node)?;
        if key.object_name.to_lowercase().contains(&needle) {
            out.push_str(&format!(
                "{}
",
                key.object_name
            ));
        }
    }
    Ok(out)
}

pub(crate) fn render_find_column(
    store: &GraphStore,
    snapshot_key: &str,
    query: &str,
) -> Result<String, String> {
    let needle = query.to_lowercase();
    let mut out = String::new();
    for node in store
        .nodes_by_label(snapshot_key, "Column")
        .map_err(|err| err.to_string())?
    {
        let key = object_key(&node)?;
        let column_name = key.sub_object.as_deref().unwrap_or(&key.object_name);
        if column_name.to_lowercase().contains(&needle) {
            out.push_str(&format!(
                "{}.{}
",
                key.object_name, column_name
            ));
        }
    }
    Ok(out)
}

fn required_node(
    store: &GraphStore,
    snapshot_key: &str,
    node_key: &str,
) -> Result<GraphNodeRecord, String> {
    store
        .get_node(snapshot_key, node_key)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("graph node '{node_key}' not found"))
}

fn object_key(node: &GraphNodeRecord) -> Result<ObjectKey, String> {
    node.node_key
        .parse()
        .map_err(|err| format!("invalid graph node key '{}': {err}", node.node_key))
}

fn column_from_node(node: &GraphNodeRecord) -> Result<ColumnObject, String> {
    serde_json::from_str(&node.payload_json).map_err(|_| old_cache_error(node))
}

fn constraint_from_node(node: &GraphNodeRecord) -> Result<ConstraintObject, String> {
    serde_json::from_str(&node.payload_json).map_err(|_| old_cache_error(node))
}

fn foreign_key_from_node(node: &GraphNodeRecord) -> Result<ConstraintObject, String> {
    let constraint = constraint_from_node(node)?;
    if constraint.kind == ConstraintKind::ForeignKey {
        Ok(constraint)
    } else {
        Err(format!(
            "graph node '{}' is not a foreign key",
            node.node_key
        ))
    }
}

fn index_from_node(node: &GraphNodeRecord) -> Result<IndexObject, String> {
    serde_json::from_str(&node.payload_json).map_err(|_| old_cache_error(node))
}

fn old_cache_error(node: &GraphNodeRecord) -> String {
    format!(
        "graph node '{}' is missing metadata payload; re-run index for this alias",
        node.node_key
    )
}

fn foreign_key_description(constraint: &ConstraintObject) -> ForeignKeyDescription {
    ForeignKeyDescription {
        name: constraint.name.clone(),
        table: constraint.table_key.object_name.clone(),
        columns: names_from_keys(&constraint.columns),
        referenced_table: constraint
            .referenced_table_key
            .as_ref()
            .map(|key| key.object_name.clone())
            .unwrap_or_default(),
        referenced_columns: names_from_keys(&constraint.referenced_columns),
    }
}

fn names_from_keys(keys: &[ObjectKey]) -> Vec<String> {
    keys.iter()
        .map(|key| {
            key.sub_object
                .clone()
                .unwrap_or_else(|| key.object_name.clone())
        })
        .collect()
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_owned()
    } else {
        values.join(", ")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use database_memory_core::graph_builder::insert_schema_snapshot_graph;
    use database_memory_core::{
        AdapterCapabilities, CapabilitySupport, DatabaseObject, ObjectKind, SchemaObject,
        SchemaSnapshot, TableKind, TableObject,
    };

    const SNAPSHOT: &str = "sqlite:sample";

    #[test]
    fn describes_and_finds_cached_graph_metadata() {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &snapshot()).unwrap();

        let description = describe_table(&store, SNAPSHOT, "orders").unwrap();
        let text = render_table_description(&description, OutputFormat::Text);
        let json = render_table_description(&description, OutputFormat::Json);

        assert!(text.contains("user_id INTEGER nullable: no"));
        assert!(text.contains("fk_orders_user: orders(user_id) -> users(id)"));
        assert!(json.contains(r#""table": "orders""#));
        assert_eq!(
            render_find_table(&store, SNAPSHOT, "ord").unwrap(),
            "orders\n"
        );
        assert_eq!(
            render_find_column(&store, SNAPSHOT, "USER").unwrap(),
            "orders.user_id\n"
        );
    }

    fn snapshot() -> SchemaSnapshot {
        let database = key(ObjectKind::Database, "main", None);
        let schema = key(ObjectKind::Schema, "main", None);
        let users = key(ObjectKind::Table, "users", None);
        let orders = key(ObjectKind::Table, "orders", None);
        let users_id = key(ObjectKind::Column, "users", Some("id"));
        let orders_id = key(ObjectKind::Column, "orders", Some("id"));
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));

        SchemaSnapshot {
            source_kind: "sqlite".to_owned(),
            connection_alias: "sample".to_owned(),
            database: DatabaseObject {
                key: database.clone(),
                name: "main".to_owned(),
            },
            schemas: vec![SchemaObject {
                key: schema.clone(),
                database_key: database,
                name: "main".to_owned(),
            }],
            tables: vec![
                TableObject {
                    key: users.clone(),
                    schema_key: schema.clone(),
                    name: "users".to_owned(),
                    kind: TableKind::BaseTable,
                },
                TableObject {
                    key: orders.clone(),
                    schema_key: schema,
                    name: "orders".to_owned(),
                    kind: TableKind::BaseTable,
                },
            ],
            columns: vec![
                column(users_id.clone(), users.clone(), "id", 1),
                column(orders_id.clone(), orders.clone(), "id", 1),
                column(orders_user_id.clone(), orders.clone(), "user_id", 2),
            ],
            constraints: vec![
                ConstraintObject {
                    key: key(ObjectKind::PrimaryKey, "orders", Some("pk_orders")),
                    table_key: orders.clone(),
                    name: "pk_orders".to_owned(),
                    kind: ConstraintKind::PrimaryKey,
                    columns: vec![orders_id],
                    referenced_table_key: None,
                    referenced_columns: vec![],
                    expression: None,
                },
                ConstraintObject {
                    key: key(ObjectKind::ForeignKey, "orders", Some("fk_orders_user")),
                    table_key: orders.clone(),
                    name: "fk_orders_user".to_owned(),
                    kind: ConstraintKind::ForeignKey,
                    columns: vec![orders_user_id.clone()],
                    referenced_table_key: Some(users.clone()),
                    referenced_columns: vec![users_id.clone()],
                    expression: None,
                },
                ConstraintObject {
                    key: key(ObjectKind::PrimaryKey, "users", Some("pk_users")),
                    table_key: users,
                    name: "pk_users".to_owned(),
                    kind: ConstraintKind::PrimaryKey,
                    columns: vec![users_id],
                    referenced_table_key: None,
                    referenced_columns: vec![],
                    expression: None,
                },
            ],
            indexes: vec![IndexObject {
                key: key(ObjectKind::Index, "orders", Some("idx_orders_user_id")),
                table_key: orders,
                name: "idx_orders_user_id".to_owned(),
                columns: vec![orders_user_id],
                is_unique: false,
                is_primary: false,
                predicate: None,
                expression: None,
            }],
            views: vec![],
            triggers: vec![],
            routines: vec![],
            capabilities: AdapterCapabilities {
                source_kind: "sqlite".to_owned(),
                metadata_only: true,
                schemas: true,
                tables: true,
                columns: true,
                constraints: true,
                indexes: true,
                views: CapabilitySupport::Unsupported,
                triggers: CapabilitySupport::Unsupported,
                routines: CapabilitySupport::Unsupported,
                dependencies: CapabilitySupport::Unsupported,
                notes: vec![],
            },
        }
    }

    fn column(
        key: ObjectKey,
        table_key: ObjectKey,
        name: &str,
        ordinal_position: u32,
    ) -> ColumnObject {
        ColumnObject {
            key,
            table_key,
            name: name.to_owned(),
            ordinal_position,
            data_type: "INTEGER".to_owned(),
            is_nullable: false,
            default_value: None,
            is_generated: false,
        }
    }

    fn key(kind: ObjectKind, object_name: &str, sub_object: Option<&str>) -> ObjectKey {
        ObjectKey::new(
            "sqlite",
            "sample",
            "main",
            "main",
            kind,
            object_name,
            sub_object.map(str::to_owned),
        )
    }
}
