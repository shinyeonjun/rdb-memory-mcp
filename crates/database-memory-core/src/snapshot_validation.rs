use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ConstraintKind, ObjectKey, ObjectKind, SchemaSnapshot, TableKind};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotValidationIssue {
    pub code: String,
    pub object_key: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotValidationError {
    pub issues: Vec<SnapshotValidationIssue>,
}

const MAX_METADATA_TEXT_BYTES: usize = 1_048_576;

impl fmt::Display for SnapshotValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "schema snapshot validation failed with {} issue(s)",
            self.issues.len()
        )?;
        if let Some(issue) = self.issues.first() {
            write!(f, ": {} [{}]", issue.message, issue.object_key)?;
        }
        Ok(())
    }
}

impl Error for SnapshotValidationError {}

pub fn validate_schema_snapshot(snapshot: &SchemaSnapshot) -> Result<(), SnapshotValidationError> {
    let mut validator = SnapshotValidator::default();

    if snapshot.source_kind.trim().is_empty() {
        validator.issue(
            "snapshot_source_missing",
            &snapshot.database.key,
            "snapshot source kind must not be empty",
        );
    }
    if snapshot.connection_alias.trim().is_empty() {
        validator.issue(
            "connection_alias_missing",
            &snapshot.database.key,
            "snapshot connection alias must not be empty",
        );
    }
    if snapshot.capabilities.source_kind != snapshot.source_kind {
        validator.issue(
            "capability_source_mismatch",
            &snapshot.database.key,
            "capability source kind must match the snapshot source kind",
        );
    }

    validator.register(&snapshot.database.key, ObjectKind::Database);
    for schema in &snapshot.schemas {
        validator.register(&schema.key, ObjectKind::Schema);
    }
    for table in &snapshot.tables {
        validator.register(&table.key, ObjectKind::Table);
    }
    let mut column_ordinals = BTreeSet::new();
    for column in &snapshot.columns {
        validator.register(&column.key, ObjectKind::Column);
    }
    for constraint in &snapshot.constraints {
        validator.register(&constraint.key, constraint_object_kind(constraint.kind));
    }
    for index in &snapshot.indexes {
        validator.register(&index.key, ObjectKind::Index);
    }
    for view in &snapshot.views {
        validator.register(&view.key, ObjectKind::View);
    }
    for trigger in &snapshot.triggers {
        validator.register(&trigger.key, ObjectKind::Trigger);
    }
    for routine in &snapshot.routines {
        validator.register(&routine.key, ObjectKind::Routine);
    }
    validator.validate_registered_scope(&snapshot.connection_alias, &snapshot.database.key);

    validator.validate_identity(
        &snapshot.database.key,
        &snapshot.connection_alias,
        &snapshot.database.name,
        None,
    );
    if snapshot.database.key.database != snapshot.database.name {
        validator.issue(
            "database_identity_mismatch",
            &snapshot.database.key,
            "database key scope must match the database name",
        );
    }
    for schema in &snapshot.schemas {
        validator.require_kind(&schema.database_key, ObjectKind::Database, &schema.key);
        validator.validate_identity(&schema.key, &snapshot.connection_alias, &schema.name, None);
        if schema.key.schema != schema.name {
            validator.issue(
                "schema_identity_mismatch",
                &schema.key,
                "schema key scope must match the schema name",
            );
        }
    }
    for table in &snapshot.tables {
        validator.require_kind(&table.schema_key, ObjectKind::Schema, &table.key);
        validator.validate_identity(&table.key, &snapshot.connection_alias, &table.name, None);
        if table.kind == TableKind::Temporary && table.key.schema.is_empty() {
            validator.issue(
                "invalid_table_scope",
                &table.key,
                "temporary table is missing a schema identity",
            );
        }
    }
    for column in &snapshot.columns {
        validator.require_kind(&column.table_key, ObjectKind::Table, &column.key);
        validator.require_child_of(&column.key, &column.table_key, &column.key);
        validator.validate_identity(
            &column.key,
            &snapshot.connection_alias,
            &column.table_key.object_name,
            Some(&column.name),
        );
        if column.ordinal_position == 0 {
            validator.issue(
                "invalid_column_ordinal",
                &column.key,
                "column ordinal position must be at least 1",
            );
        }
        if !column_ordinals.insert((column.table_key.to_string(), column.ordinal_position)) {
            validator.issue(
                "duplicate_column_ordinal",
                &column.key,
                "two columns in the same table share an ordinal position",
            );
        }
        validate_bounded_text(
            &mut validator,
            &column.key,
            column.default_value.as_deref(),
            "column_default_too_large",
        );
    }
    for constraint in &snapshot.constraints {
        validator.require_kind(&constraint.table_key, ObjectKind::Table, &constraint.key);
        validator.require_child_of(&constraint.key, &constraint.table_key, &constraint.key);
        validator.validate_identity(
            &constraint.key,
            &snapshot.connection_alias,
            &constraint.table_key.object_name,
            Some(&constraint.name),
        );
        for column in &constraint.columns {
            validator.require_column_of(column, &constraint.table_key, &constraint.key);
        }
        if has_duplicate_keys(&constraint.columns) {
            validator.issue(
                "duplicate_constraint_column",
                &constraint.key,
                "constraint contains the same source column more than once",
            );
        }
        if has_duplicate_keys(&constraint.referenced_columns) {
            validator.issue(
                "duplicate_constraint_reference_column",
                &constraint.key,
                "constraint contains the same referenced column more than once",
            );
        }
        validate_bounded_text(
            &mut validator,
            &constraint.key,
            constraint.expression.as_deref(),
            "constraint_expression_too_large",
        );
        match constraint.kind {
            ConstraintKind::PrimaryKey | ConstraintKind::Unique => {
                if constraint.columns.is_empty() {
                    validator.issue(
                        "constraint_columns_missing",
                        &constraint.key,
                        "key constraint has no resolved columns",
                    );
                }
                if constraint.referenced_table_key.is_some()
                    || !constraint.referenced_columns.is_empty()
                {
                    validator.issue(
                        "unexpected_constraint_reference",
                        &constraint.key,
                        "non-foreign-key constraint contains a referenced target",
                    );
                }
            }
            ConstraintKind::ForeignKey => {
                if constraint.columns.is_empty() {
                    validator.issue(
                        "foreign_key_columns_missing",
                        &constraint.key,
                        "foreign key has no resolved source columns",
                    );
                }
                match &constraint.referenced_table_key {
                    Some(table_key) => {
                        validator.require_kind(table_key, ObjectKind::Table, &constraint.key);
                        for column in &constraint.referenced_columns {
                            validator.require_column_of(column, table_key, &constraint.key);
                        }
                    }
                    None => validator.issue(
                        "foreign_key_target_missing",
                        &constraint.key,
                        "foreign key has no resolved target table",
                    ),
                }
                if constraint.columns.len() != constraint.referenced_columns.len() {
                    validator.issue(
                        "foreign_key_cardinality_mismatch",
                        &constraint.key,
                        "foreign key source and target column counts differ",
                    );
                }
            }
            ConstraintKind::Check => {
                if constraint
                    .expression
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default()
                    .is_empty()
                {
                    validator.issue(
                        "check_expression_missing",
                        &constraint.key,
                        "check constraint has no expression",
                    );
                }
            }
        }
    }
    for index in &snapshot.indexes {
        validator.require_kind(&index.table_key, ObjectKind::Table, &index.key);
        validator.require_child_of(&index.key, &index.table_key, &index.key);
        validator.validate_identity(
            &index.key,
            &snapshot.connection_alias,
            &index.table_key.object_name,
            Some(&index.name),
        );
        for column in &index.columns {
            validator.require_column_of(column, &index.table_key, &index.key);
        }
        if has_duplicate_keys(&index.columns) {
            validator.issue(
                "duplicate_index_column",
                &index.key,
                "index contains the same resolved column more than once",
            );
        }
        if index.columns.is_empty()
            && index
                .expression
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
        {
            validator.issue(
                "index_definition_missing",
                &index.key,
                "index has neither resolved columns nor an expression",
            );
        }
        validate_bounded_text(
            &mut validator,
            &index.key,
            index.predicate.as_deref(),
            "index_predicate_too_large",
        );
        validate_bounded_text(
            &mut validator,
            &index.key,
            index.expression.as_deref(),
            "index_expression_too_large",
        );
    }
    for view in &snapshot.views {
        validator.require_kind(&view.schema_key, ObjectKind::Schema, &view.key);
        validator.validate_identity(&view.key, &snapshot.connection_alias, &view.name, None);
        for dependency in &view.depends_on {
            validator.require_any(dependency, &view.key);
        }
        if has_duplicate_keys(&view.depends_on) {
            validator.issue(
                "duplicate_view_dependency",
                &view.key,
                "view dependency is duplicated",
            );
        }
        validate_bounded_text(
            &mut validator,
            &view.key,
            view.definition.as_deref(),
            "view_definition_too_large",
        );
    }
    for trigger in &snapshot.triggers {
        validator.require_one_of(
            &trigger.table_key,
            &[ObjectKind::Table, ObjectKind::View],
            &trigger.key,
        );
        validator.require_child_of(&trigger.key, &trigger.table_key, &trigger.key);
        validator.validate_identity(
            &trigger.key,
            &snapshot.connection_alias,
            &trigger.table_key.object_name,
            Some(&trigger.name),
        );
        if trigger.events.is_empty() {
            validator.issue(
                "trigger_events_missing",
                &trigger.key,
                "trigger must declare at least one event",
            );
        }
        if has_duplicate_strings(&trigger.events) {
            validator.issue(
                "duplicate_trigger_event",
                &trigger.key,
                "trigger event is duplicated",
            );
        }
        validate_bounded_text(
            &mut validator,
            &trigger.key,
            trigger.definition.as_deref(),
            "trigger_definition_too_large",
        );
        if let Some(routine_key) = &trigger.executes_routine_key {
            validator.require_kind(routine_key, ObjectKind::Routine, &trigger.key);
        }
    }
    for routine in &snapshot.routines {
        validator.require_kind(&routine.schema_key, ObjectKind::Schema, &routine.key);
        validator.validate_identity(
            &routine.key,
            &snapshot.connection_alias,
            &routine.name,
            routine.key.sub_object.as_deref(),
        );
        for dependency in &routine.depends_on {
            validator.require_any(dependency, &routine.key);
        }
        if has_duplicate_keys(&routine.depends_on) {
            validator.issue(
                "duplicate_routine_dependency",
                &routine.key,
                "routine dependency is duplicated",
            );
        }
        validate_bounded_text(
            &mut validator,
            &routine.key,
            routine.definition.as_deref(),
            "routine_definition_too_large",
        );
    }

    if validator.issues.is_empty() {
        Ok(())
    } else {
        Err(SnapshotValidationError {
            issues: validator.issues,
        })
    }
}

fn has_duplicate_keys(keys: &[ObjectKey]) -> bool {
    let mut seen = BTreeSet::new();
    keys.iter().any(|key| !seen.insert(key.to_string()))
}

fn has_duplicate_strings(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn validate_bounded_text(
    validator: &mut SnapshotValidator,
    key: &ObjectKey,
    value: Option<&str>,
    code: &str,
) {
    if value.is_some_and(|value| value.len() > MAX_METADATA_TEXT_BYTES) {
        validator.issue(code, key, "metadata text exceeds the canonical size limit");
    }
}

fn constraint_object_kind(kind: ConstraintKind) -> ObjectKind {
    match kind {
        ConstraintKind::PrimaryKey => ObjectKind::PrimaryKey,
        ConstraintKind::ForeignKey => ObjectKind::ForeignKey,
        ConstraintKind::Unique => ObjectKind::UniqueConstraint,
        ConstraintKind::Check => ObjectKind::CheckConstraint,
    }
}

#[derive(Default)]
struct SnapshotValidator {
    objects: BTreeMap<String, ObjectKey>,
    issues: Vec<SnapshotValidationIssue>,
}

impl SnapshotValidator {
    fn register(&mut self, key: &ObjectKey, expected_kind: ObjectKind) {
        if key.object_kind != expected_kind {
            self.issue(
                "object_kind_mismatch",
                key,
                &format!(
                    "object kind is {}, expected {expected_kind}",
                    key.object_kind
                ),
            );
        }
        let stable_key = key.to_string();
        if self.objects.insert(stable_key, key.clone()).is_some() {
            self.issue(
                "duplicate_object_key",
                key,
                "stable object key is duplicated",
            );
        }
    }

    fn validate_identity(
        &mut self,
        key: &ObjectKey,
        connection_alias: &str,
        object_name: &str,
        sub_object: Option<&str>,
    ) {
        if key.connection_alias != connection_alias {
            self.issue(
                "connection_alias_mismatch",
                key,
                "object connection alias differs from the snapshot alias",
            );
        }
        if key.object_name != object_name || key.sub_object.as_deref() != sub_object {
            self.issue(
                "object_identity_mismatch",
                key,
                "stable object identity differs from the object payload",
            );
        }
    }

    fn validate_registered_scope(&mut self, connection_alias: &str, database: &ObjectKey) {
        let keys = self.objects.values().cloned().collect::<Vec<_>>();
        for key in keys {
            if key.connection_alias != connection_alias {
                self.issue(
                    "connection_alias_mismatch",
                    &key,
                    "object connection alias differs from the snapshot alias",
                );
            }
            if key.source_kind.trim().is_empty()
                || key.database.trim().is_empty()
                || key.schema.trim().is_empty()
                || key.object_name.trim().is_empty()
            {
                self.issue(
                    "object_identity_incomplete",
                    &key,
                    "stable object identity contains an empty required component",
                );
            }
            if key.source_kind != database.source_kind || key.database != database.database {
                self.issue(
                    "object_source_scope_mismatch",
                    &key,
                    "object source and database scope differ from the snapshot database identity",
                );
            }
        }
    }

    fn require_any(&mut self, target: &ObjectKey, owner: &ObjectKey) {
        if !self.objects.contains_key(&target.to_string()) {
            self.issue(
                "relationship_target_missing",
                owner,
                &format!("relationship target {target} is not present in the snapshot"),
            );
        }
    }

    fn require_kind(&mut self, target: &ObjectKey, kind: ObjectKind, owner: &ObjectKey) {
        self.require_one_of(target, &[kind], owner);
    }

    fn require_one_of(&mut self, target: &ObjectKey, kinds: &[ObjectKind], owner: &ObjectKey) {
        match self.objects.get(&target.to_string()) {
            Some(actual) if kinds.contains(&actual.object_kind) => {}
            Some(actual) => self.issue(
                "relationship_target_kind_mismatch",
                owner,
                &format!(
                    "relationship target {target} has kind {}, expected one of {}",
                    actual.object_kind,
                    kinds
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
            None => self.issue(
                "relationship_target_missing",
                owner,
                &format!("relationship target {target} is not present in the snapshot"),
            ),
        }
    }

    fn require_child_of(&mut self, child: &ObjectKey, parent: &ObjectKey, owner: &ObjectKey) {
        if child.database != parent.database || child.schema != parent.schema {
            self.issue(
                "object_scope_mismatch",
                owner,
                &format!("child {child} and parent {parent} have different scopes"),
            );
        }
    }

    fn require_column_of(&mut self, column: &ObjectKey, table: &ObjectKey, owner: &ObjectKey) {
        self.require_kind(column, ObjectKind::Column, owner);
        if column.database != table.database
            || column.schema != table.schema
            || column.object_name != table.object_name
        {
            self.issue(
                "column_owner_mismatch",
                owner,
                &format!("column {column} does not belong to table {table}"),
            );
        }
    }

    fn issue(&mut self, code: &str, object_key: &ObjectKey, message: &str) {
        self.issues.push(SnapshotValidationIssue {
            code: code.to_owned(),
            object_key: object_key.to_string(),
            message: message.to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterCapabilities, CapabilitySupport, ColumnObject, ConstraintObject, DatabaseObject,
        SchemaObject, TableObject,
    };

    #[test]
    fn valid_snapshot_passes() {
        assert!(validate_schema_snapshot(&snapshot()).is_ok());
    }

    #[test]
    fn duplicate_keys_and_dangling_relationships_fail_together() {
        let mut snapshot = snapshot();
        snapshot.columns.push(snapshot.columns[0].clone());
        snapshot.constraints[0].referenced_table_key =
            Some(key(ObjectKind::Table, "missing", None));

        let error = validate_schema_snapshot(&snapshot).unwrap_err();
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "duplicate_object_key"));
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "relationship_target_missing"));
    }

    #[test]
    fn foreign_key_requires_equal_resolved_column_counts() {
        let mut snapshot = snapshot();
        snapshot.constraints[0].referenced_columns.clear();

        let error = validate_schema_snapshot(&snapshot).unwrap_err();
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "foreign_key_cardinality_mismatch"));
    }

    #[test]
    fn duplicate_ordinals_and_cross_source_keys_are_rejected() {
        let mut snapshot = snapshot();
        let mut duplicate_ordinal = snapshot.columns[0].clone();
        duplicate_ordinal.key = key(ObjectKind::Column, "users", Some("other_id"));
        duplicate_ordinal.name = "other_id".to_owned();
        snapshot.columns.push(duplicate_ordinal);
        snapshot.tables[0].key.source_kind = "other-rdb".to_owned();

        let error = validate_schema_snapshot(&snapshot).unwrap_err();

        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "duplicate_column_ordinal"));
        assert!(error
            .issues
            .iter()
            .any(|issue| issue.code == "object_source_scope_mismatch"));
    }

    fn snapshot() -> SchemaSnapshot {
        let database_key = key(ObjectKind::Database, "main", None);
        let schema_key = key(ObjectKind::Schema, "main", None);
        let users_key = key(ObjectKind::Table, "users", None);
        let orders_key = key(ObjectKind::Table, "orders", None);
        let users_id = key(ObjectKind::Column, "users", Some("id"));
        let orders_user_id = key(ObjectKind::Column, "orders", Some("user_id"));

        SchemaSnapshot {
            source_kind: "sqlite".to_owned(),
            connection_alias: "sample".to_owned(),
            database: DatabaseObject {
                key: database_key.clone(),
                name: "main".to_owned(),
            },
            schemas: vec![SchemaObject {
                key: schema_key.clone(),
                database_key,
                name: "main".to_owned(),
            }],
            tables: vec![
                TableObject {
                    key: users_key.clone(),
                    schema_key: schema_key.clone(),
                    name: "users".to_owned(),
                    kind: TableKind::BaseTable,
                },
                TableObject {
                    key: orders_key.clone(),
                    schema_key,
                    name: "orders".to_owned(),
                    kind: TableKind::BaseTable,
                },
            ],
            columns: vec![
                column(users_id.clone(), users_key.clone(), "id", 1),
                column(orders_user_id.clone(), orders_key.clone(), "user_id", 1),
            ],
            constraints: vec![ConstraintObject {
                key: key(ObjectKind::ForeignKey, "orders", Some("fk_orders_users")),
                table_key: orders_key,
                name: "fk_orders_users".to_owned(),
                kind: ConstraintKind::ForeignKey,
                columns: vec![orders_user_id],
                referenced_table_key: Some(users_key),
                referenced_columns: vec![users_id],
                expression: None,
            }],
            indexes: vec![],
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
                views: CapabilitySupport::Supported,
                triggers: CapabilitySupport::Supported,
                routines: CapabilitySupport::Unsupported,
                dependencies: CapabilitySupport::Partial,
                limitations: vec![],
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
            data_type: "integer".to_owned(),
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
