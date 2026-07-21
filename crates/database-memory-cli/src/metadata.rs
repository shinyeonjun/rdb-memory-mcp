use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use database_memory_core::graph_store::{GraphNodeRecord, GraphStore};
use database_memory_core::impact_analysis::{
    impact_analysis_bounded, Direction, ImpactAnalysisResult,
};
use database_memory_core::relationship_trace::{trace_relationships_bounded, GraphPath};
use database_memory_core::{
    capability_warnings, ColumnObject, ConstraintKind, ConstraintObject, IndexObject, ObjectKey,
    ObjectKind, SchemaSnapshot, TableObject,
};
use serde_json::json;

use crate::{
    args::{OutputFormat, MAX_INVENTORY_TABLES, MAX_RESULT_LIMIT, MAX_TRAVERSAL_DEPTH},
    PRODUCT_CONTRACT_VERSION,
};

pub(crate) fn open_existing_store(cache_path: &Path) -> Result<GraphStore, String> {
    if !cache_path.exists() {
        return Err(format!(
            "cache path '{}' not found; run index first",
            cache_path.display()
        ));
    }
    GraphStore::open(cache_path).map_err(|err| err.to_string())
}

pub(crate) fn resolve_snapshot_key(store: &GraphStore, selector: &str) -> Result<String, String> {
    if store
        .get_snapshot(selector)
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Ok(selector.to_owned());
    }

    let matches = store
        .list_snapshots()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|snapshot| {
            snapshot
                .snapshot_key
                .split_once(':')
                .map(|(_, alias)| alias == selector)
                .unwrap_or(false)
        })
        .map(|snapshot| snapshot.snapshot_key)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [snapshot_key] => Ok(snapshot_key.clone()),
        [] => Err(format!(
            "snapshot selector '{selector}' not found in cache; run index first"
        )),
        _ => Err(format!(
            "snapshot alias '{selector}' is ambiguous; use one snapshot key: {}",
            matches.join(", ")
        )),
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
    snapshot_key: String,
    table_key: String,
    table_name: String,
    columns: Vec<ColumnObject>,
    primary_key: Vec<String>,
    constraints: Vec<ConstraintObject>,
    outbound_foreign_keys: Vec<ForeignKeyDescription>,
    inbound_foreign_keys: Vec<ForeignKeyDescription>,
    indexes: Vec<IndexObject>,
    dependents: Vec<DependentObjectDescription>,
    capability_warnings: Vec<String>,
}

struct ForeignKeyDescription {
    key: String,
    table_key: String,
    name: String,
    table: String,
    columns: Vec<String>,
    column_keys: Vec<String>,
    referenced_table_key: Option<String>,
    referenced_table: String,
    referenced_columns: Vec<String>,
    referenced_column_keys: Vec<String>,
}

#[derive(Clone)]
struct DependentObjectDescription {
    key: String,
    kind: String,
    name: String,
    relation: String,
    column_keys: Vec<String>,
}

pub(crate) fn describe_table(
    store: &GraphStore,
    snapshot_key: &str,
    table_object_key: Option<&str>,
    table_name: Option<&str>,
) -> Result<TableDescription, String> {
    let table = resolve_table_node(store, snapshot_key, table_object_key, table_name)?;
    let table_key = object_key(&table)?;
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
    let dependents = table_dependents(store, snapshot_key, &table.node_key, &columns)?;

    Ok(TableDescription {
        snapshot_key: snapshot_key.to_owned(),
        table_key: table.node_key.clone(),
        table_name: table_key.object_name,
        columns,
        primary_key,
        constraints,
        outbound_foreign_keys,
        inbound_foreign_keys,
        indexes: table_indexes(store, snapshot_key, &table.node_key)?,
        dependents,
        capability_warnings: snapshot_capability_warnings(store, snapshot_key)?,
    })
}

fn table_dependents(
    store: &GraphStore,
    snapshot_key: &str,
    table_key: &str,
    columns: &[ColumnObject],
) -> Result<Vec<DependentObjectDescription>, String> {
    let mut dependents = BTreeMap::<String, DependentObjectDescription>::new();
    for edge in store
        .edges_to(snapshot_key, table_key)
        .map_err(|error| error.to_string())?
    {
        if matches!(
            edge.edge_type.as_str(),
            "VIEW_DEPENDS_ON_TABLE" | "ROUTINE_DEPENDS_ON_TABLE"
        ) {
            let node = required_node(store, snapshot_key, &edge.edge_from)?;
            merge_dependent(
                &mut dependents,
                dependent_from_node(&node, &edge.edge_type)?,
                None,
            );
        }
    }
    for column in columns {
        for edge in store
            .edges_to(snapshot_key, &column.key.to_string())
            .map_err(|error| error.to_string())?
        {
            if matches!(
                edge.edge_type.as_str(),
                "VIEW_DEPENDS_ON_COLUMN" | "ROUTINE_DEPENDS_ON_COLUMN"
            ) {
                let node = required_node(store, snapshot_key, &edge.edge_from)?;
                merge_dependent(
                    &mut dependents,
                    dependent_from_node(&node, &edge.edge_type)?,
                    Some(column.key.to_string()),
                );
            }
        }
    }
    for edge in store
        .edges_from(snapshot_key, table_key)
        .map_err(|error| error.to_string())?
    {
        if edge.edge_type == "TABLE_HAS_TRIGGER" {
            let node = required_node(store, snapshot_key, &edge.edge_to)?;
            merge_dependent(
                &mut dependents,
                dependent_from_node(&node, &edge.edge_type)?,
                None,
            );
        }
    }
    Ok(dependents.into_values().collect())
}

fn dependent_from_node(
    node: &GraphNodeRecord,
    relation: &str,
) -> Result<DependentObjectDescription, String> {
    let key = object_key(node)?;
    let kind = match key.object_kind {
        ObjectKind::View => "view",
        ObjectKind::Trigger => "trigger",
        ObjectKind::Routine => "routine",
        _ => {
            return Err(format!(
                "graph node '{}' is not a DB dependent object",
                node.node_key
            ))
        }
    };
    let relation = match relation {
        "VIEW_DEPENDS_ON_TABLE" | "VIEW_DEPENDS_ON_COLUMN" => "view_depends_on",
        "ROUTINE_DEPENDS_ON_TABLE" | "ROUTINE_DEPENDS_ON_COLUMN" => "routine_depends_on",
        "TABLE_HAS_TRIGGER" => "table_has_trigger",
        _ => relation,
    };
    Ok(DependentObjectDescription {
        key: node.node_key.clone(),
        kind: kind.to_owned(),
        name: node
            .display_name
            .clone()
            .unwrap_or_else(|| key.object_name.clone()),
        relation: relation.to_owned(),
        column_keys: Vec::new(),
    })
}

fn merge_dependent(
    dependents: &mut BTreeMap<String, DependentObjectDescription>,
    dependent: DependentObjectDescription,
    column_key: Option<String>,
) {
    let entry = dependents.entry(dependent.key.clone()).or_insert(dependent);
    if let Some(column_key) = column_key {
        if !entry.column_keys.contains(&column_key) {
            entry.column_keys.push(column_key);
            entry.column_keys.sort();
        }
    }
}

fn find_table_node(
    store: &GraphStore,
    snapshot_key: &str,
    table_name: &str,
) -> Result<GraphNodeRecord, String> {
    let mut matches = store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter_map(|node| match object_key(&node) {
            Ok(key) if key.object_name == table_name => Some(Ok(node)),
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    matches.sort_by(|left, right| left.node_key.cmp(&right.node_key));

    match matches.len() {
        0 => Err(format!(
            "table '{table_name}' not found in snapshot '{snapshot_key}'"
        )),
        1 => Ok(matches.remove(0)),
        _ => Err(format!(
            "table '{table_name}' is ambiguous in snapshot '{snapshot_key}'; use --object-key with one of: {}",
            matches
                .iter()
                .map(|node| node.node_key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn resolve_table_node(
    store: &GraphStore,
    snapshot_key: &str,
    table_object_key: Option<&str>,
    table_name: Option<&str>,
) -> Result<GraphNodeRecord, String> {
    match (table_object_key, table_name) {
        (Some(object_key), None) => {
            let node = required_node(store, snapshot_key, object_key)?;
            let key = self::object_key(&node)?;
            if node.label != "Table" || key.object_kind != ObjectKind::Table {
                return Err(format!("graph node '{object_key}' is not a table"));
            }
            Ok(node)
        }
        (None, Some(table_name)) => find_table_node(store, snapshot_key, table_name),
        _ => Err("pass one table selector: a table name or --object-key".to_owned()),
    }
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
    out.push_str("dependents:\n");
    if description.dependents.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for dependent in &description.dependents {
            out.push_str(&format!(
                "  {} {} via {}\n",
                dependent.kind, dependent.name, dependent.relation
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
    json_line(table_description_json_value(description))
}

fn table_description_json_value(description: &TableDescription) -> serde_json::Value {
    json!({
        "contract_version": PRODUCT_CONTRACT_VERSION,
        "snapshot_key": &description.snapshot_key,
        "table_key": &description.table_key,
        "table": &description.table_name,
        "columns": description.columns.iter().map(|column| json!({
            "key": column.key.to_string(),
            "table_key": column.table_key.to_string(),
            "schema": &column.key.schema,
            "database": &column.key.database,
            "name": &column.name,
            "type": &column.data_type,
            "nullable": column.is_nullable,
        })).collect::<Vec<_>>(),
        "primary_key": &description.primary_key,
        "constraints": description.constraints.iter().map(|constraint| json!({
            "key": constraint.key.to_string(),
            "table_key": constraint.table_key.to_string(),
            "name": &constraint.name,
            "kind": constraint_kind_name(constraint.kind),
            "columns": names_from_keys(&constraint.columns),
            "column_keys": keys_as_strings(&constraint.columns),
            "referenced_table_key": constraint.referenced_table_key.as_ref().map(ToString::to_string),
            "referenced_columns": names_from_keys(&constraint.referenced_columns),
            "referenced_column_keys": keys_as_strings(&constraint.referenced_columns),
            "expression": &constraint.expression,
        })).collect::<Vec<_>>(),
        "foreign_keys": {
            "outbound": foreign_keys_json(&description.outbound_foreign_keys),
            "inbound": foreign_keys_json(&description.inbound_foreign_keys),
        },
        "indexes": description.indexes.iter().map(|index| json!({
            "key": index.key.to_string(),
            "table_key": index.table_key.to_string(),
            "name": &index.name,
            "columns": names_from_keys(&index.columns),
            "column_keys": keys_as_strings(&index.columns),
            "unique": index.is_unique,
            "primary": index.is_primary,
            "predicate": &index.predicate,
            "expression": &index.expression,
        })).collect::<Vec<_>>(),
        "dependents": description.dependents.iter().map(|dependent| json!({
            "key": &dependent.key,
            "kind": &dependent.kind,
            "name": &dependent.name,
            "relation": &dependent.relation,
            "column_keys": &dependent.column_keys,
        })).collect::<Vec<_>>(),
        "capability_warnings": &description.capability_warnings,
    })
}

pub(crate) fn render_inventory(
    store: &GraphStore,
    snapshot_key: &str,
    offset: usize,
    limit_requested: usize,
) -> Result<String, String> {
    let record = store
        .get_snapshot(snapshot_key)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("snapshot '{snapshot_key}' not found in cache; run index first"))?;
    let snapshot =
        serde_json::from_str::<SchemaSnapshot>(&record.payload_json).map_err(|error| {
            format!("snapshot '{snapshot_key}' payload is incompatible; re-index it: {error}")
        })?;
    let warnings = capability_warnings(&snapshot.capabilities);
    let index = InventoryDescriptionIndex::new(&snapshot);
    let mut table_entries = snapshot
        .tables
        .iter()
        .map(|table| (table.key.to_string(), table))
        .collect::<Vec<_>>();
    table_entries.sort_by(|left, right| left.0.cmp(&right.0));

    let total_tables = table_entries.len();
    let (limit_applied, limit_clamped) = inventory_bounds(limit_requested);
    let mut tables = Vec::with_capacity(total_tables.saturating_sub(offset).min(limit_applied));
    for (table_key, table) in table_entries.into_iter().skip(offset).take(limit_applied) {
        let description = index.describe(snapshot_key, table_key, table, &warnings);
        tables.push(table_description_json_value(&description));
    }
    let next_offset = offset.saturating_add(tables.len());
    let has_more = next_offset < total_tables;

    Ok(json_line(json!({
        "contract_version": PRODUCT_CONTRACT_VERSION,
        "snapshot_key": snapshot_key,
        "offset": offset,
        "limit_requested": limit_requested,
        "limit_applied": limit_applied,
        "limit_clamped": limit_clamped,
        "result_count": tables.len(),
        "total_tables": total_tables,
        "has_more": has_more,
        "next_offset": has_more.then_some(next_offset),
        "truncated": has_more,
        "capability_warnings": warnings,
        "tables": tables,
    })))
}

struct InventoryDescriptionIndex<'a> {
    columns: HashMap<String, Vec<&'a ColumnObject>>,
    constraints: HashMap<String, Vec<&'a ConstraintObject>>,
    inbound_foreign_keys: HashMap<String, Vec<&'a ConstraintObject>>,
    indexes: HashMap<String, Vec<&'a IndexObject>>,
    dependents: HashMap<String, BTreeMap<String, DependentObjectDescription>>,
}

impl<'a> InventoryDescriptionIndex<'a> {
    fn new(snapshot: &'a SchemaSnapshot) -> Self {
        let mut index = Self {
            columns: HashMap::new(),
            constraints: HashMap::new(),
            inbound_foreign_keys: HashMap::new(),
            indexes: HashMap::new(),
            dependents: HashMap::new(),
        };
        for column in &snapshot.columns {
            index
                .columns
                .entry(column.table_key.to_string())
                .or_default()
                .push(column);
        }
        for constraint in &snapshot.constraints {
            index
                .constraints
                .entry(constraint.table_key.to_string())
                .or_default()
                .push(constraint);
            if constraint.kind == ConstraintKind::ForeignKey {
                if let Some(referenced_table) = &constraint.referenced_table_key {
                    index
                        .inbound_foreign_keys
                        .entry(referenced_table.to_string())
                        .or_default()
                        .push(constraint);
                }
            }
        }
        for item in &snapshot.indexes {
            index
                .indexes
                .entry(item.table_key.to_string())
                .or_default()
                .push(item);
        }
        let column_tables = snapshot
            .columns
            .iter()
            .map(|column| (column.key.to_string(), column.table_key.to_string()))
            .collect::<HashMap<_, _>>();
        for view in &snapshot.views {
            index.record_dependencies(
                &view.key,
                &view.name,
                "view",
                "view_depends_on",
                &view.depends_on,
                &column_tables,
            );
        }
        for routine in &snapshot.routines {
            index.record_dependencies(
                &routine.key,
                &routine.name,
                "routine",
                "routine_depends_on",
                &routine.depends_on,
                &column_tables,
            );
        }
        for trigger in &snapshot.triggers {
            if trigger.table_key.object_kind == ObjectKind::Table {
                index.record_dependent(
                    trigger.table_key.to_string(),
                    &trigger.key,
                    &trigger.name,
                    "trigger",
                    "table_has_trigger",
                    None,
                );
            }
        }
        index
    }

    fn record_dependencies(
        &mut self,
        key: &ObjectKey,
        name: &str,
        kind: &str,
        relation: &str,
        dependencies: &[ObjectKey],
        column_tables: &HashMap<String, String>,
    ) {
        for dependency in dependencies {
            match dependency.object_kind {
                ObjectKind::Table => {
                    self.record_dependent(dependency.to_string(), key, name, kind, relation, None)
                }
                ObjectKind::Column => {
                    if let Some(table_key) = column_tables.get(&dependency.to_string()) {
                        self.record_dependent(
                            table_key.clone(),
                            key,
                            name,
                            kind,
                            relation,
                            Some(dependency.to_string()),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn record_dependent(
        &mut self,
        table_key: String,
        key: &ObjectKey,
        name: &str,
        kind: &str,
        relation: &str,
        column_key: Option<String>,
    ) {
        merge_dependent(
            self.dependents.entry(table_key).or_default(),
            DependentObjectDescription {
                key: key.to_string(),
                kind: kind.to_owned(),
                name: name.to_owned(),
                relation: relation.to_owned(),
                column_keys: Vec::new(),
            },
            column_key,
        );
    }

    fn describe(
        &self,
        snapshot_key: &str,
        table_key: String,
        table: &TableObject,
        capability_warnings: &[String],
    ) -> TableDescription {
        let mut columns = self
            .columns
            .get(&table_key)
            .into_iter()
            .flatten()
            .map(|column| (*column).clone())
            .collect::<Vec<_>>();
        columns.sort_by_key(|column| column.ordinal_position);
        let mut constraints = self
            .constraints
            .get(&table_key)
            .into_iter()
            .flatten()
            .map(|constraint| (*constraint).clone())
            .collect::<Vec<_>>();
        constraints.sort_by_key(|constraint| constraint.key.to_string());
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
        let mut inbound_foreign_keys = self
            .inbound_foreign_keys
            .get(&table_key)
            .into_iter()
            .flatten()
            .map(|constraint| foreign_key_description(constraint))
            .collect::<Vec<_>>();
        inbound_foreign_keys.sort_by(|left, right| left.name.cmp(&right.name));
        let mut indexes = self
            .indexes
            .get(&table_key)
            .into_iter()
            .flatten()
            .map(|index| (*index).clone())
            .collect::<Vec<_>>();
        indexes.sort_by(|left, right| left.name.cmp(&right.name));
        let dependents = self
            .dependents
            .get(&table_key)
            .into_iter()
            .flat_map(|items| items.values().cloned())
            .collect();

        TableDescription {
            snapshot_key: snapshot_key.to_owned(),
            table_key,
            table_name: table.name.clone(),
            columns,
            primary_key,
            constraints,
            outbound_foreign_keys,
            inbound_foreign_keys,
            indexes,
            dependents,
            capability_warnings: capability_warnings.to_vec(),
        }
    }
}

fn inventory_bounds(limit_requested: usize) -> (usize, bool) {
    let limit_applied = limit_requested.min(MAX_INVENTORY_TABLES);
    (limit_applied, limit_requested != limit_applied)
}

fn constraint_kind_name(kind: ConstraintKind) -> &'static str {
    match kind {
        ConstraintKind::PrimaryKey => "primary_key",
        ConstraintKind::ForeignKey => "foreign_key",
        ConstraintKind::Unique => "unique",
        ConstraintKind::Check => "check",
    }
}

fn foreign_keys_json(foreign_keys: &[ForeignKeyDescription]) -> Vec<serde_json::Value> {
    foreign_keys
        .iter()
        .map(|fk| {
            json!({
                "key": &fk.key,
                "table_key": &fk.table_key,
                "name": &fk.name,
                "table": &fk.table,
                "columns": &fk.columns,
                "column_keys": &fk.column_keys,
                "referenced_table_key": &fk.referenced_table_key,
                "referenced_table": &fk.referenced_table,
                "referenced_columns": &fk.referenced_columns,
                "referenced_column_keys": &fk.referenced_column_keys,
            })
        })
        .collect()
}

pub(crate) fn render_find_table(
    store: &GraphStore,
    snapshot_key: &str,
    query: &str,
    format: OutputFormat,
) -> Result<String, String> {
    let needle = query.to_lowercase();
    let mut table_matches = Vec::new();
    for node in store
        .nodes_by_label(snapshot_key, "Table")
        .map_err(|err| err.to_string())?
    {
        let key = object_key(&node)?;
        if key.object_name.to_lowercase().contains(&needle) {
            table_matches.push((key.to_string(), key.object_name, key.schema, key.database));
        }
    }
    table_matches.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| left.2.cmp(&right.2))
            .then_with(|| left.3.cmp(&right.3))
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut tables = table_matches
        .iter()
        .map(|(_, name, _, _)| name.clone())
        .collect::<Vec<_>>();
    tables.sort();
    match format {
        OutputFormat::Text => Ok(lines(&tables)),
        OutputFormat::Json => Ok(json_line(json!({
            "tables": tables,
            "table_matches": table_matches.into_iter().map(|(table_key, name, schema, database)| json!({
                "table_key": table_key,
                "name": name,
                "schema": schema,
                "database": database,
            })).collect::<Vec<_>>(),
        }))),
    }
}

pub(crate) fn render_find_column(
    store: &GraphStore,
    snapshot_key: &str,
    query: &str,
    format: OutputFormat,
) -> Result<String, String> {
    let needle = query.to_lowercase();
    let mut columns = Vec::new();
    for node in store
        .nodes_by_label(snapshot_key, "Column")
        .map_err(|err| err.to_string())?
    {
        let column = column_from_node(&node)?;
        let key = &column.key;
        let column_name = column.name.clone();
        if column_name.to_lowercase().contains(&needle) {
            let column_key = key.to_string();
            let table_key = ObjectKey::new(
                key.source_kind.clone(),
                key.connection_alias.clone(),
                key.database.clone(),
                key.schema.clone(),
                ObjectKind::Table,
                key.object_name.clone(),
                None,
            )
            .to_string();
            columns.push(json!({
                "key": &column_key,
                "column_key": column_key,
                "table_key": table_key,
                "schema": key.schema,
                "database": key.database,
                "table": key.object_name,
                "column": column_name,
                "ordinal_position": column.ordinal_position,
                "type": column.data_type,
                "nullable": column.is_nullable,
                "default_value": column.default_value,
                "generated": column.is_generated,
            }));
        }
    }
    columns.sort_by(|left, right| {
        left["table"]
            .as_str()
            .cmp(&right["table"].as_str())
            .then_with(|| left["column"].as_str().cmp(&right["column"].as_str()))
            .then_with(|| left["key"].as_str().cmp(&right["key"].as_str()))
    });
    match format {
        OutputFormat::Text => Ok(lines(
            &columns
                .iter()
                .map(|column| {
                    format!(
                        "{}.{}",
                        column["table"].as_str().unwrap_or_default(),
                        column["column"].as_str().unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>(),
        )),
        OutputFormat::Json => Ok(json_line(json!({ "columns": columns }))),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_impact_analysis(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: Option<&str>,
    table_name: Option<&str>,
    column_name: Option<&str>,
    direction: Direction,
    max_depth_requested: u32,
    result_limit_requested: usize,
) -> Result<String, String> {
    let object_key =
        resolve_impact_object_key(store, snapshot_key, object_key, table_name, column_name)?;
    let max_depth = max_depth_requested.min(MAX_TRAVERSAL_DEPTH);
    let result_limit = result_limit_requested.min(MAX_RESULT_LIMIT);
    let bounded = impact_analysis_bounded(
        store,
        snapshot_key,
        &object_key,
        direction,
        max_depth,
        result_limit,
    )
    .map_err(|err| err.to_string())?;
    let result_count = bounded
        .result
        .groups
        .iter()
        .map(|group| group.nodes.len())
        .sum::<usize>();

    Ok(json_line(json!({
        "contract_version": PRODUCT_CONTRACT_VERSION,
        "snapshot_key": snapshot_key,
        "object_key": object_key,
        "direction": direction_name(direction),
        "max_depth_requested": max_depth_requested,
        "max_depth_applied": max_depth,
        "max_depth_clamped": max_depth_requested != max_depth,
        "result_limit_requested": result_limit_requested,
        "result_limit_applied": result_limit,
        "result_limit_clamped": result_limit_requested != result_limit,
        "result_count": result_count,
        "truncated": bounded.truncated,
        "groups": impact_groups_json(&bounded.result),
        "capability_warnings": snapshot_capability_warnings(store, snapshot_key)?,
    })))
}

pub(crate) fn render_relationship_trace(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: &str,
    direction: Direction,
    max_depth_requested: u32,
    result_limit_requested: usize,
) -> Result<String, String> {
    required_node(store, snapshot_key, object_key)?;
    let max_depth = max_depth_requested.min(MAX_TRAVERSAL_DEPTH);
    let result_limit = result_limit_requested.min(MAX_RESULT_LIMIT);
    let bounded = trace_relationships_bounded(
        store,
        snapshot_key,
        object_key,
        direction,
        max_depth,
        result_limit,
    )
    .map_err(|err| err.to_string())?;

    Ok(json_line(json!({
        "contract_version": PRODUCT_CONTRACT_VERSION,
        "snapshot_key": snapshot_key,
        "start_object_key": object_key,
        "direction": direction_name(direction),
        "max_depth_requested": max_depth_requested,
        "max_depth_applied": max_depth,
        "max_depth_clamped": max_depth_requested != max_depth,
        "result_limit_requested": result_limit_requested,
        "result_limit_applied": result_limit,
        "result_limit_clamped": result_limit_requested != result_limit,
        "result_count": bounded.paths.len(),
        "truncated": bounded.truncated,
        "paths": relationship_paths_json(&bounded.paths),
        "capability_warnings": snapshot_capability_warnings(store, snapshot_key)?,
    })))
}

fn resolve_impact_object_key(
    store: &GraphStore,
    snapshot_key: &str,
    object_key: Option<&str>,
    table_name: Option<&str>,
    column_name: Option<&str>,
) -> Result<String, String> {
    if let Some(object_key) = object_key {
        required_node(store, snapshot_key, object_key)?;
        return Ok(object_key.to_owned());
    }

    let table_name = table_name.ok_or("pass --object-key or --table")?;
    let table = resolve_table_node(store, snapshot_key, None, Some(table_name))?;
    let Some(column_name) = column_name else {
        return Ok(table.node_key);
    };

    table_columns(store, snapshot_key, &table.node_key)?
        .into_iter()
        .find(|column| column.name == column_name)
        .map(|column| column.key.to_string())
        .ok_or_else(|| format!("column '{column_name}' not found on table '{table_name}'"))
}

fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
        Direction::Both => "both",
    }
}

fn impact_groups_json(result: &ImpactAnalysisResult) -> Vec<serde_json::Value> {
    result
        .groups
        .iter()
        .map(|group| {
            json!({
                "label": &group.label,
                "depth": group.depth,
                "nodes": group.nodes.iter().map(|node| json!({
                    "node_key": &node.node_key,
                    "label": &node.label,
                    "display_name": &node.display_name,
                    "depth": node.depth,
                    "edge_type": &node.edge_type_used,
                    "edge_from": &node.edge_from,
                    "edge_to": &node.edge_to,
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn relationship_paths_json(paths: &[GraphPath]) -> Vec<serde_json::Value> {
    paths
        .iter()
        .map(|path| {
            json!({
                "depth": path.hops.len().saturating_sub(1),
                "hops": path.hops.iter().enumerate().map(|(depth, hop)| json!({
                    "node_key": &hop.node_key,
                    "label": &hop.label,
                    "depth": depth,
                    "edge_type": &hop.edge_type_used,
                    "edge_from": &hop.edge_from,
                    "edge_to": &hop.edge_to,
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn lines(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("{value}\n"))
        .collect::<String>()
}

fn json_line(value: serde_json::Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(&value).unwrap())
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
        key: constraint.key.to_string(),
        table_key: constraint.table_key.to_string(),
        name: constraint.name.clone(),
        table: constraint.table_key.object_name.clone(),
        columns: names_from_keys(&constraint.columns),
        column_keys: keys_as_strings(&constraint.columns),
        referenced_table_key: constraint
            .referenced_table_key
            .as_ref()
            .map(ToString::to_string),
        referenced_table: constraint
            .referenced_table_key
            .as_ref()
            .map(|key| key.object_name.clone())
            .unwrap_or_default(),
        referenced_columns: names_from_keys(&constraint.referenced_columns),
        referenced_column_keys: keys_as_strings(&constraint.referenced_columns),
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

fn keys_as_strings(keys: &[ObjectKey]) -> Vec<String> {
    keys.iter().map(ToString::to_string).collect()
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
    use database_memory_core::graph_store::GraphSnapshotRecord;
    use database_memory_core::{
        AdapterCapabilities, CapabilitySupport, DatabaseObject, ObjectKind, RoutineKind,
        RoutineObject, SchemaObject, SchemaSnapshot, TableKind, TableObject, TriggerObject,
        ViewObject,
    };

    const SNAPSHOT: &str = "sqlite:sample";

    #[test]
    fn describes_and_finds_cached_graph_metadata() {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &snapshot()).unwrap();

        let description = describe_table(&store, SNAPSHOT, None, Some("orders")).unwrap();
        let text = render_table_description(&description, OutputFormat::Text);
        let json = render_table_description(&description, OutputFormat::Json);

        assert!(text.contains("user_id INTEGER nullable: no"));
        assert!(text.contains("fk_orders_user: orders(user_id) -> users(id)"));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["contract_version"], PRODUCT_CONTRACT_VERSION);
        assert_eq!(value["snapshot_key"], SNAPSHOT);
        assert_eq!(value["table"], "orders");
        assert!(value["table_key"]
            .as_str()
            .is_some_and(|key| key.contains(":table:orders")));
        assert!(value["constraints"].as_array().is_some_and(|constraints| {
            constraints
                .iter()
                .any(|constraint| constraint["kind"] == "foreign_key")
        }));
        assert_eq!(value["columns"][1]["name"], "user_id");
        assert!(value["columns"][1]["key"]
            .as_str()
            .is_some_and(|key| { key == "sqlite:sample:main:main:column:orders:user_id" }));
        assert_eq!(
            value["columns"][1]["table_key"],
            "sqlite:sample:main:main:table:orders"
        );
        assert_eq!(value["columns"][1]["schema"], "main");
        assert_eq!(value["columns"][1]["database"], "main");
        let foreign_key = value["constraints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|constraint| constraint["kind"] == "foreign_key")
            .unwrap();
        assert_eq!(foreign_key["columns"][0], "user_id");
        assert_eq!(
            foreign_key["column_keys"][0],
            "sqlite:sample:main:main:column:orders:user_id"
        );
        assert_eq!(
            foreign_key["referenced_column_keys"][0],
            "sqlite:sample:main:main:column:users:id"
        );
        assert!(value["indexes"][0].get("predicate").is_some());
        assert!(value["indexes"][0].get("expression").is_some());
        assert!(value["indexes"][0]["key"]
            .as_str()
            .is_some_and(|key| key.contains(":index:orders:")));
        assert!(value["foreign_keys"]["outbound"][0]["key"]
            .as_str()
            .is_some_and(|key| key.contains(":foreign_key:orders:")));
        assert!(value["foreign_keys"]["outbound"][0]["table_key"]
            .as_str()
            .is_some_and(|key| key.contains(":table:orders")));
        assert!(value["foreign_keys"]["outbound"][0]["referenced_table_key"]
            .as_str()
            .is_some_and(|key| key.contains(":table:users")));
        assert_eq!(
            value["foreign_keys"]["outbound"][0]["column_keys"][0],
            "sqlite:sample:main:main:column:orders:user_id"
        );
        assert_eq!(
            value["foreign_keys"]["outbound"][0]["referenced_column_keys"][0],
            "sqlite:sample:main:main:column:users:id"
        );
        assert_eq!(value["indexes"][0]["columns"][0], "user_id");
        assert_eq!(
            value["indexes"][0]["column_keys"][0],
            "sqlite:sample:main:main:column:orders:user_id"
        );
        assert_eq!(
            render_find_table(&store, SNAPSHOT, "ord", OutputFormat::Text).unwrap(),
            "orders\n"
        );
        assert_eq!(
            render_find_column(&store, SNAPSHOT, "USER", OutputFormat::Text).unwrap(),
            "orders.user_id\n"
        );

        let found_columns: serde_json::Value = serde_json::from_str(
            &render_find_column(&store, SNAPSHOT, "USER", OutputFormat::Json).unwrap(),
        )
        .unwrap();
        assert_eq!(found_columns["columns"][0]["table"], "orders");
        assert_eq!(found_columns["columns"][0]["column"], "user_id");
        assert_eq!(
            found_columns["columns"][0]["key"],
            "sqlite:sample:main:main:column:orders:user_id"
        );
        assert_eq!(
            found_columns["columns"][0]["column_key"],
            "sqlite:sample:main:main:column:orders:user_id"
        );
        assert_eq!(
            found_columns["columns"][0]["table_key"],
            "sqlite:sample:main:main:table:orders"
        );
        assert_eq!(found_columns["columns"][0]["schema"], "main");
        assert_eq!(found_columns["columns"][0]["database"], "main");
        assert_eq!(found_columns["columns"][0]["type"], "INTEGER");
        assert_eq!(found_columns["columns"][0]["nullable"], false);
        assert_eq!(found_columns["columns"][0]["generated"], false);
    }

    #[test]
    fn inventory_and_describe_include_direct_view_trigger_and_routine_dependents() {
        let mut source = snapshot();
        let orders = key(ObjectKind::Table, "orders", None);
        let user_id = key(ObjectKind::Column, "orders", Some("user_id"));
        source.views.push(ViewObject {
            key: key(ObjectKind::View, "order_users", None),
            schema_key: key(ObjectKind::Schema, "main", None),
            name: "order_users".to_owned(),
            definition: None,
            depends_on: vec![orders.clone(), user_id.clone()],
        });
        source.triggers.push(TriggerObject {
            key: key(ObjectKind::Trigger, "orders", Some("orders_touch")),
            table_key: orders.clone(),
            name: "orders_touch".to_owned(),
            timing: Some("AFTER".to_owned()),
            events: vec!["UPDATE".to_owned()],
            definition: None,
            executes_routine_key: None,
        });
        source.routines.push(RoutineObject {
            key: key(ObjectKind::Routine, "refresh_orders", None),
            schema_key: key(ObjectKind::Schema, "main", None),
            name: "refresh_orders".to_owned(),
            kind: RoutineKind::Function,
            definition: None,
            depends_on: vec![orders.clone(), user_id.clone()],
        });
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &source).unwrap();

        let inventory: serde_json::Value =
            serde_json::from_str(&render_inventory(&store, SNAPSHOT, 0, 10).unwrap()).unwrap();
        let table = inventory["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["table_key"] == orders.to_string())
            .unwrap();
        let dependents = table["dependents"].as_array().unwrap();

        assert_eq!(dependents.len(), 3);
        assert!(dependents.iter().any(|dependent| {
            dependent["kind"] == "view"
                && dependent["name"] == "order_users"
                && dependent["column_keys"] == json!([user_id.to_string()])
        }));
        assert!(dependents.iter().any(|dependent| {
            dependent["kind"] == "trigger"
                && dependent["relation"] == "table_has_trigger"
                && dependent["column_keys"] == json!([])
        }));

        let described = describe_table(&store, SNAPSHOT, Some(&orders.to_string()), None).unwrap();
        assert_eq!(table, &table_description_json_value(&described));
    }

    #[test]
    fn snapshot_selector_supports_non_sqlite_aliases_and_rejects_ambiguity() {
        let store = GraphStore::in_memory().unwrap();
        for snapshot_key in ["postgres:shared", "mysql:shared"] {
            store
                .insert_snapshot(&GraphSnapshotRecord {
                    snapshot_key: snapshot_key.to_owned(),
                    source: Some(snapshot_key.to_owned()),
                    captured_at_unix_ms: 0,
                    payload_json: "{}".to_owned(),
                })
                .unwrap();
        }

        assert_eq!(
            resolve_snapshot_key(&store, "postgres:shared").unwrap(),
            "postgres:shared"
        );
        let error = resolve_snapshot_key(&store, "shared").unwrap_err();
        assert!(error.contains("ambiguous"));
        assert!(error.contains("mysql:shared"));
        assert!(error.contains("postgres:shared"));
    }

    #[test]
    fn duplicate_table_names_require_a_stable_key_and_find_keeps_legacy_names() {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &multi_schema_snapshot()).unwrap();

        let main_key = key(ObjectKind::Table, "orders", None).to_string();
        let audit_key = key_in_schema("audit", ObjectKind::Table, "orders", None).to_string();
        let ambiguity = describe_table(&store, SNAPSHOT, None, Some("orders"))
            .err()
            .unwrap();
        assert!(ambiguity.contains("ambiguous"));
        assert!(ambiguity.contains(&main_key));
        assert!(ambiguity.contains(&audit_key));

        let selected = describe_table(&store, SNAPSHOT, Some(&audit_key), None).unwrap();
        assert_eq!(selected.table_key, audit_key);
        assert_eq!(selected.table_name, "orders");

        let found: serde_json::Value = serde_json::from_str(
            &render_find_table(&store, SNAPSHOT, "orders", OutputFormat::Json).unwrap(),
        )
        .unwrap();
        assert_eq!(found["tables"], json!(["orders", "orders"]));
        assert_eq!(found["table_matches"].as_array().unwrap().len(), 2);
        let match_keys = found["table_matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["table_key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(match_keys, vec![audit_key.as_str(), main_key.as_str()]);
        assert_eq!(found["table_matches"][0]["name"], "orders");
        assert_eq!(found["table_matches"][0]["schema"], "audit");
        assert_eq!(found["table_matches"][0]["database"], "main");

        let impact_error = render_impact_analysis(
            &store,
            SNAPSHOT,
            None,
            Some("orders"),
            None,
            Direction::Both,
            1,
            10,
        )
        .unwrap_err();
        assert_eq!(impact_error, ambiguity);
    }

    #[test]
    fn inventory_json_is_bounded_sorted_and_matches_describe_table_shape() {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &multi_schema_snapshot()).unwrap();

        let warnings = json!([
            "view dependency metadata is not tracked by the sqlite adapter.",
            "trigger dependency metadata is not tracked by the sqlite adapter.",
            "routine dependency metadata is not tracked by the sqlite adapter.",
            "cross-object dependency metadata is not tracked by the sqlite adapter."
        ]);
        let inventory: serde_json::Value =
            serde_json::from_str(&render_inventory(&store, SNAPSHOT, 0, 1).unwrap()).unwrap();
        assert_eq!(
            inventory,
            json!({
                "contract_version": PRODUCT_CONTRACT_VERSION,
                "snapshot_key": SNAPSHOT,
                "offset": 0,
                "limit_requested": 1,
                "limit_applied": 1,
                "limit_clamped": false,
                "result_count": 1,
                "total_tables": 3,
                "has_more": true,
                "next_offset": 1,
                "truncated": true,
                "capability_warnings": warnings,
                "tables": [{
                    "contract_version": PRODUCT_CONTRACT_VERSION,
                    "snapshot_key": SNAPSHOT,
                    "table_key": "sqlite:sample:main:audit:table:orders",
                    "table": "orders",
                    "columns": [{
                        "key": "sqlite:sample:main:audit:column:orders:id",
                        "table_key": "sqlite:sample:main:audit:table:orders",
                        "schema": "audit",
                        "database": "main",
                        "name": "id",
                        "type": "INTEGER",
                        "nullable": false
                    }],
                    "primary_key": [],
                    "constraints": [],
                    "foreign_keys": { "outbound": [], "inbound": [] },
                    "indexes": [],
                    "dependents": [],
                    "capability_warnings": warnings
                }]
            })
        );

        let all: serde_json::Value =
            serde_json::from_str(&render_inventory(&store, SNAPSHOT, 0, 10).unwrap()).unwrap();
        let table_keys = all["tables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|table| table["table_key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(table_keys.windows(2).all(|keys| keys[0] < keys[1]));
        assert_eq!(
            all["tables"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|table| table["table"] == "orders")
                .count(),
            2
        );

        let main_orders = describe_table(
            &store,
            SNAPSHOT,
            Some("sqlite:sample:main:main:table:orders"),
            None,
        )
        .unwrap();
        assert_eq!(
            all["tables"]
                .as_array()
                .unwrap()
                .iter()
                .find(|table| table["table_key"] == main_orders.table_key)
                .unwrap(),
            &table_description_json_value(&main_orders)
        );

        assert_eq!(
            inventory_bounds(MAX_INVENTORY_TABLES + 1),
            (MAX_INVENTORY_TABLES, true)
        );

        let second_page: serde_json::Value =
            serde_json::from_str(&render_inventory(&store, SNAPSHOT, 1, 1).unwrap()).unwrap();
        assert_eq!(second_page["offset"], 1);
        assert_eq!(second_page["result_count"], 1);
        assert_eq!(second_page["next_offset"], 2);
        assert_ne!(
            second_page["tables"][0]["table_key"],
            inventory["tables"][0]["table_key"]
        );

        let exhausted: serde_json::Value =
            serde_json::from_str(&render_inventory(&store, SNAPSHOT, 3, 1).unwrap()).unwrap();
        assert_eq!(exhausted["tables"], json!([]));
        assert_eq!(exhausted["has_more"], false);
        assert_eq!(exhausted["next_offset"], serde_json::Value::Null);
        assert_eq!(exhausted["truncated"], false);
    }

    #[test]
    fn renders_bounded_impact_and_trace_contracts() {
        let store = GraphStore::in_memory().unwrap();
        insert_schema_snapshot_graph(&store, SNAPSHOT, 0, &snapshot()).unwrap();

        let impact: serde_json::Value = serde_json::from_str(
            &render_impact_analysis(
                &store,
                SNAPSHOT,
                None,
                Some("orders"),
                Some("user_id"),
                Direction::Outbound,
                99,
                1,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(impact["contract_version"], PRODUCT_CONTRACT_VERSION);
        assert_eq!(impact["snapshot_key"], SNAPSHOT);
        assert_eq!(impact["max_depth_applied"], MAX_TRAVERSAL_DEPTH);
        assert_eq!(impact["max_depth_clamped"], true);
        assert_eq!(impact["result_count"], 1);
        assert_eq!(impact["truncated"], true);
        assert!(impact["groups"][0]["nodes"][0]["edge_type"].is_string());
        assert!(impact["groups"][0]["nodes"][0]["edge_from"].is_string());
        assert!(impact["groups"][0]["nodes"][0]["edge_to"].is_string());
        assert!(impact["capability_warnings"].is_array());

        let start = key(ObjectKind::Column, "orders", Some("user_id")).to_string();
        let trace: serde_json::Value = serde_json::from_str(
            &render_relationship_trace(&store, SNAPSHOT, &start, Direction::Outbound, 2, 1)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(trace["start_object_key"], start);
        assert_eq!(trace["direction"], "outbound");
        assert_eq!(trace["result_count"], 1);
        assert_eq!(trace["truncated"], true);
        assert_eq!(trace["paths"][0]["hops"][1]["depth"], 1);
        assert!(trace["paths"][0]["hops"][1]["edge_type"].is_string());
        assert!(trace["paths"][0]["hops"][1]["edge_from"].is_string());
        assert!(trace["paths"][0]["hops"][1]["edge_to"].is_string());
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
                limitations: vec![],
                notes: vec![],
            },
        }
    }

    fn multi_schema_snapshot() -> SchemaSnapshot {
        let mut snapshot = snapshot();
        let audit_schema = key_in_schema("audit", ObjectKind::Schema, "audit", None);
        let audit_orders = key_in_schema("audit", ObjectKind::Table, "orders", None);
        let audit_orders_id = key_in_schema("audit", ObjectKind::Column, "orders", Some("id"));
        snapshot.schemas.push(SchemaObject {
            key: audit_schema.clone(),
            database_key: snapshot.database.key.clone(),
            name: "audit".to_owned(),
        });
        snapshot.tables.push(TableObject {
            key: audit_orders.clone(),
            schema_key: audit_schema,
            name: "orders".to_owned(),
            kind: TableKind::BaseTable,
        });
        snapshot
            .columns
            .push(column(audit_orders_id, audit_orders, "id", 1));
        snapshot
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
        key_in_schema("main", kind, object_name, sub_object)
    }

    fn key_in_schema(
        schema: &str,
        kind: ObjectKind,
        object_name: &str,
        sub_object: Option<&str>,
    ) -> ObjectKey {
        ObjectKey::new(
            "sqlite",
            "sample",
            "main",
            schema,
            kind,
            object_name,
            sub_object.map(str::to_owned),
        )
    }
}
