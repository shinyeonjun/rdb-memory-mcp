use std::collections::BTreeMap;

use sqlite3_parser::ast::{
    Cmd, ColFlags, ColumnConstraint, CreateTableBody, DeferSubclause, Expr, InitDeferredPred, Name,
    NullsOrder, RefAct, RefArg, ResolveType, SortOrder, Stmt, TabFlags, TableConstraint,
    TriggerEvent, TriggerTime,
};
use sqlite3_parser::lexer::sql::Parser;
use sqlite3_parser::{Bump, FallibleIterator};

use crate::canonical::MetadataValue;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedTableDefinition {
    pub name: String,
    pub strict: bool,
    pub without_rowid: bool,
    pub columns: Vec<ParsedColumnDefinition>,
    pub constraints: Vec<ParsedConstraint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedColumnDefinition {
    pub name: String,
    pub generated_expression: Option<String>,
    pub generated_storage: Option<String>,
    pub collation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParsedConstraintKind {
    PrimaryKey,
    ForeignKey,
    Unique,
    Check,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedConstraint {
    pub name: Option<String>,
    pub kind: ParsedConstraintKind,
    pub columns: Vec<String>,
    pub referenced_table: Option<String>,
    pub referenced_columns: Vec<String>,
    pub expression: Option<String>,
    pub properties: BTreeMap<String, MetadataValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedIndexDefinition {
    pub name: String,
    pub table_name: String,
    pub unique: bool,
    pub terms: Vec<ParsedIndexTerm>,
    pub predicate: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedIndexTerm {
    pub expression: String,
    pub column_name: Option<String>,
    pub order: Option<String>,
    pub nulls: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedTriggerDefinition {
    pub name: String,
    pub owner_name: String,
    pub timing: String,
    pub event: String,
    pub update_columns: Vec<String>,
    pub when_expression: Option<String>,
}

pub(crate) fn parse_table_definition(sql: &str) -> Result<ParsedTableDefinition, String> {
    with_statement(sql, |statement| match statement {
        Stmt::CreateTable { tbl_name, body, .. } => parse_create_table(name(&tbl_name.name), body),
        _ => Err("sqlite schema entry is not a CREATE TABLE statement".to_owned()),
    })
}

pub(crate) fn parse_index_definition(sql: &str) -> Result<ParsedIndexDefinition, String> {
    with_statement(sql, |statement| match statement {
        Stmt::CreateIndex {
            unique,
            idx_name,
            tbl_name,
            columns,
            where_clause,
            ..
        } => Ok(ParsedIndexDefinition {
            name: name(&idx_name.name),
            table_name: name(tbl_name),
            unique: *unique,
            terms: columns
                .iter()
                .map(|column| ParsedIndexTerm {
                    expression: column.expr.to_string(),
                    column_name: expression_column_name(&column.expr),
                    order: column.order.map(sort_order),
                    nulls: column.nulls.map(nulls_order),
                })
                .collect(),
            predicate: where_clause.as_ref().map(ToString::to_string),
        }),
        _ => Err("sqlite schema entry is not a CREATE INDEX statement".to_owned()),
    })
}

pub(crate) fn parse_trigger_definition(sql: &str) -> Result<ParsedTriggerDefinition, String> {
    with_statement(sql, |statement| match statement {
        Stmt::CreateTrigger {
            trigger_name,
            time,
            event,
            tbl_name,
            when_clause,
            ..
        } => {
            let (event, update_columns) = trigger_event(event);
            Ok(ParsedTriggerDefinition {
                name: name(&trigger_name.name),
                owner_name: name(&tbl_name.name),
                timing: time.map(trigger_time).unwrap_or("BEFORE").to_owned(),
                event: event.to_owned(),
                update_columns,
                when_expression: when_clause.as_ref().map(ToString::to_string),
            })
        }
        _ => Err("sqlite schema entry is not a CREATE TRIGGER statement".to_owned()),
    })
}

pub(crate) fn validate_schema_ddl(sql: &str) -> Result<usize, String> {
    let bump = Bump::new();
    let mut parser = Parser::new(&bump, sql.as_bytes());
    let mut statement_count = 0_usize;
    while let Some(command) = parser.next().map_err(|error| error.to_string())? {
        let statement = match command {
            Cmd::Stmt(statement) => statement,
            Cmd::Explain(_) | Cmd::ExplainQueryPlan(_) => {
                return Err("EXPLAIN statements are not schema DDL".to_owned());
            }
        };
        validate_schema_statement(&statement)?;
        statement_count += 1;
    }
    Ok(statement_count)
}

fn validate_schema_statement(statement: &Stmt<'_>) -> Result<(), String> {
    match statement {
        Stmt::AlterTable(..)
        | Stmt::CreateIndex { .. }
        | Stmt::DropIndex { .. }
        | Stmt::DropTable { .. }
        | Stmt::DropTrigger { .. }
        | Stmt::DropView { .. }
        | Stmt::Begin(..)
        | Stmt::Commit(..)
        | Stmt::Release(..)
        | Stmt::Rollback { .. }
        | Stmt::Savepoint(..) => Ok(()),
        Stmt::CreateTable {
            temporary, body, ..
        } => {
            if *temporary {
                Err("temporary tables are outside the certified main schema".to_owned())
            } else if matches!(body, CreateTableBody::AsSelect(_)) {
                Err(
                    "CREATE TABLE AS SELECT can read application rows and is not schema-only DDL"
                        .to_owned(),
                )
            } else {
                Ok(())
            }
        }
        Stmt::CreateTrigger { temporary, .. } => {
            if *temporary {
                Err("temporary triggers are outside the certified main schema".to_owned())
            } else {
                Ok(())
            }
        }
        Stmt::CreateView { temporary, .. } => {
            if *temporary {
                Err("temporary views are outside the certified main schema".to_owned())
            } else {
                Ok(())
            }
        }
        Stmt::Pragma(qualified_name, _) => {
            let pragma = name(&qualified_name.name).to_ascii_lowercase();
            if matches!(
                pragma.as_str(),
                "foreign_keys" | "defer_foreign_keys" | "legacy_alter_table" | "recursive_triggers"
            ) {
                Ok(())
            } else {
                Err(format!(
                    "PRAGMA {pragma} is not allowed in certified schema-only DDL"
                ))
            }
        }
        Stmt::CreateVirtualTable { .. } => Err(
            "CREATE VIRTUAL TABLE may invoke external modules and is not accepted from DDL files"
                .to_owned(),
        ),
        Stmt::Analyze(..)
        | Stmt::Attach { .. }
        | Stmt::Delete { .. }
        | Stmt::Detach(..)
        | Stmt::Insert { .. }
        | Stmt::Reindex { .. }
        | Stmt::Select(..)
        | Stmt::Update { .. }
        | Stmt::Vacuum(..) => Err(format!(
            "{} is not allowed in certified schema-only DDL",
            statement_kind(statement)
        )),
    }
}

fn statement_kind(statement: &Stmt<'_>) -> &'static str {
    match statement {
        Stmt::Analyze(..) => "ANALYZE",
        Stmt::Attach { .. } => "ATTACH",
        Stmt::Delete { .. } => "DELETE",
        Stmt::Detach(..) => "DETACH",
        Stmt::Insert { .. } => "INSERT",
        Stmt::Reindex { .. } => "REINDEX",
        Stmt::Select(..) => "SELECT",
        Stmt::Update { .. } => "UPDATE",
        Stmt::Vacuum(..) => "VACUUM",
        _ => "statement",
    }
}

fn parse_create_table(
    table_name: String,
    body: &CreateTableBody<'_>,
) -> Result<ParsedTableDefinition, String> {
    let CreateTableBody::ColumnsAndConstraints {
        columns,
        constraints,
        flags,
    } = body
    else {
        return Ok(ParsedTableDefinition {
            name: table_name,
            strict: false,
            without_rowid: false,
            columns: vec![],
            constraints: vec![],
        });
    };

    let mut parsed_columns = Vec::with_capacity(columns.len());
    let mut parsed_constraints = Vec::new();
    for column in columns {
        let column_name = name(&column.col_name);
        let mut generated_expression = None;
        let mut generated_storage = None;
        let mut collation = None;
        for named in column.constraints {
            let constraint_name = named.name.as_ref().map(name);
            match &named.constraint {
                ColumnConstraint::PrimaryKey {
                    conflict_clause,
                    auto_increment,
                    ..
                } => parsed_constraints.push(ParsedConstraint {
                    name: constraint_name,
                    kind: ParsedConstraintKind::PrimaryKey,
                    columns: vec![column_name.clone()],
                    referenced_table: None,
                    referenced_columns: vec![],
                    expression: None,
                    properties: primary_or_unique_properties(
                        *conflict_clause,
                        Some(*auto_increment),
                    ),
                }),
                ColumnConstraint::Unique(conflict_clause) => {
                    parsed_constraints.push(ParsedConstraint {
                        name: constraint_name,
                        kind: ParsedConstraintKind::Unique,
                        columns: vec![column_name.clone()],
                        referenced_table: None,
                        referenced_columns: vec![],
                        expression: None,
                        properties: primary_or_unique_properties(*conflict_clause, None),
                    });
                }
                ColumnConstraint::Check(expression) => parsed_constraints.push(ParsedConstraint {
                    name: constraint_name,
                    kind: ParsedConstraintKind::Check,
                    columns: vec![column_name.clone()],
                    referenced_table: None,
                    referenced_columns: vec![],
                    expression: Some(expression.to_string()),
                    properties: BTreeMap::new(),
                }),
                ColumnConstraint::ForeignKey {
                    clause,
                    defer_clause,
                } => parsed_constraints.push(foreign_key_constraint(
                    constraint_name,
                    vec![column_name.clone()],
                    clause,
                    defer_clause.as_ref(),
                )),
                ColumnConstraint::Generated { expr, typ } => {
                    generated_expression = Some(expr.to_string());
                    generated_storage = Some(
                        typ.as_ref()
                            .map(|value| dequote_identifier(value.0).to_ascii_uppercase())
                            .unwrap_or_else(|| "VIRTUAL".to_owned()),
                    );
                }
                ColumnConstraint::Collate { collation_name } => {
                    collation = Some(name(collation_name));
                }
                _ => {}
            }
        }
        if column.flags.intersects(ColFlags::GENERATED) && generated_expression.is_none() {
            return Err(format!(
                "generated column {column_name} has no parsed generation expression"
            ));
        }
        parsed_columns.push(ParsedColumnDefinition {
            name: column_name,
            generated_expression,
            generated_storage,
            collation,
        });
    }

    if let Some(constraints) = constraints {
        for named in *constraints {
            let constraint_name = named.name.as_ref().map(name);
            match &named.constraint {
                TableConstraint::PrimaryKey {
                    columns,
                    auto_increment,
                    conflict_clause,
                } => parsed_constraints.push(ParsedConstraint {
                    name: constraint_name,
                    kind: ParsedConstraintKind::PrimaryKey,
                    columns: columns
                        .iter()
                        .map(|column| required_column_name(&column.expr))
                        .collect::<Result<_, _>>()?,
                    referenced_table: None,
                    referenced_columns: vec![],
                    expression: None,
                    properties: primary_or_unique_properties(
                        *conflict_clause,
                        Some(*auto_increment),
                    ),
                }),
                TableConstraint::Unique {
                    columns,
                    conflict_clause,
                } => parsed_constraints.push(ParsedConstraint {
                    name: constraint_name,
                    kind: ParsedConstraintKind::Unique,
                    columns: columns
                        .iter()
                        .map(|column| required_column_name(&column.expr))
                        .collect::<Result<_, _>>()?,
                    referenced_table: None,
                    referenced_columns: vec![],
                    expression: None,
                    properties: primary_or_unique_properties(*conflict_clause, None),
                }),
                TableConstraint::Check(expression, conflict_clause) => {
                    let mut properties = BTreeMap::new();
                    insert_conflict(&mut properties, *conflict_clause);
                    parsed_constraints.push(ParsedConstraint {
                        name: constraint_name,
                        kind: ParsedConstraintKind::Check,
                        columns: vec![],
                        referenced_table: None,
                        referenced_columns: vec![],
                        expression: Some(expression.to_string()),
                        properties,
                    });
                }
                TableConstraint::ForeignKey {
                    columns,
                    clause,
                    defer_clause,
                } => parsed_constraints.push(foreign_key_constraint(
                    constraint_name,
                    columns
                        .iter()
                        .map(|column| name(&column.col_name))
                        .collect(),
                    clause,
                    defer_clause.as_ref(),
                )),
            }
        }
    }

    Ok(ParsedTableDefinition {
        name: table_name,
        strict: flags.contains(TabFlags::Strict),
        without_rowid: flags.contains(TabFlags::WithoutRowid),
        columns: parsed_columns,
        constraints: parsed_constraints,
    })
}

fn foreign_key_constraint(
    constraint_name: Option<String>,
    columns: Vec<String>,
    clause: &sqlite3_parser::ast::ForeignKeyClause<'_>,
    defer_clause: Option<&DeferSubclause>,
) -> ParsedConstraint {
    let mut properties = BTreeMap::new();
    for arg in clause.args {
        match arg {
            RefArg::OnDelete(action) => {
                insert_string(&mut properties, "on_delete", ref_action(*action))
            }
            RefArg::OnInsert(action) => {
                insert_string(&mut properties, "on_insert", ref_action(*action))
            }
            RefArg::OnUpdate(action) => {
                insert_string(&mut properties, "on_update", ref_action(*action))
            }
            RefArg::Match(value) => insert_string(&mut properties, "match", &name(value)),
        }
    }
    if let Some(defer_clause) = defer_clause {
        properties.insert(
            "deferrable".to_owned(),
            MetadataValue::Boolean(defer_clause.deferrable),
        );
        if let Some(initially) = defer_clause.init_deferred {
            insert_string(
                &mut properties,
                "initially",
                match initially {
                    InitDeferredPred::InitiallyDeferred => "deferred",
                    InitDeferredPred::InitiallyImmediate => "immediate",
                },
            );
        }
    }
    ParsedConstraint {
        name: constraint_name,
        kind: ParsedConstraintKind::ForeignKey,
        columns,
        referenced_table: Some(name(&clause.tbl_name)),
        referenced_columns: clause
            .columns
            .map(|columns| {
                columns
                    .iter()
                    .map(|column| name(&column.col_name))
                    .collect()
            })
            .unwrap_or_default(),
        expression: None,
        properties,
    }
}

fn primary_or_unique_properties(
    conflict_clause: Option<ResolveType>,
    auto_increment: Option<bool>,
) -> BTreeMap<String, MetadataValue> {
    let mut properties = BTreeMap::new();
    insert_conflict(&mut properties, conflict_clause);
    if let Some(auto_increment) = auto_increment {
        properties.insert(
            "auto_increment".to_owned(),
            MetadataValue::Boolean(auto_increment),
        );
    }
    properties
}

fn insert_conflict(
    properties: &mut BTreeMap<String, MetadataValue>,
    conflict_clause: Option<ResolveType>,
) {
    if let Some(conflict_clause) = conflict_clause {
        insert_string(properties, "on_conflict", resolve_type(conflict_clause));
    }
}

fn with_statement<T>(
    sql: &str,
    map: impl FnOnce(&Stmt<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let bump = Bump::new();
    let mut parser = Parser::new(&bump, sql.as_bytes());
    let command = parser
        .next()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "sqlite schema SQL is empty".to_owned())?;
    if parser.next().map_err(|error| error.to_string())?.is_some() {
        return Err("sqlite schema entry contains more than one statement".to_owned());
    }
    let statement = match command {
        Cmd::Stmt(statement) => statement,
        Cmd::Explain(statement) | Cmd::ExplainQueryPlan(statement) => statement,
    };
    map(&statement)
}

fn expression_column_name(expression: &Expr<'_>) -> Option<String> {
    match expression {
        Expr::Id(value) => Some(dequote_identifier(value.0)),
        Expr::Name(value) => Some(name(value)),
        Expr::Qualified(_, value) | Expr::DoublyQualified(_, _, value) => Some(name(value)),
        Expr::Collate(inner, _) => expression_column_name(inner),
        _ => None,
    }
}

fn required_column_name(expression: &Expr<'_>) -> Result<String, String> {
    expression_column_name(expression)
        .ok_or_else(|| format!("expected a column name, got expression {expression}"))
}

fn trigger_event(event: &TriggerEvent<'_>) -> (&'static str, Vec<String>) {
    match event {
        TriggerEvent::Delete => ("DELETE", vec![]),
        TriggerEvent::Insert => ("INSERT", vec![]),
        TriggerEvent::Update => ("UPDATE", vec![]),
        TriggerEvent::UpdateOf(columns) => ("UPDATE", columns.iter().map(name).collect::<Vec<_>>()),
    }
}

fn trigger_time(time: TriggerTime) -> &'static str {
    match time {
        TriggerTime::Before => "BEFORE",
        TriggerTime::After => "AFTER",
        TriggerTime::InsteadOf => "INSTEAD OF",
    }
}

fn sort_order(order: SortOrder) -> String {
    match order {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    }
    .to_owned()
}

fn nulls_order(order: NullsOrder) -> String {
    match order {
        NullsOrder::First => "FIRST",
        NullsOrder::Last => "LAST",
    }
    .to_owned()
}

fn resolve_type(value: ResolveType) -> &'static str {
    match value {
        ResolveType::Rollback => "rollback",
        ResolveType::Abort => "abort",
        ResolveType::Fail => "fail",
        ResolveType::Ignore => "ignore",
        ResolveType::Replace => "replace",
    }
}

fn ref_action(value: RefAct) -> &'static str {
    match value {
        RefAct::SetNull => "set_null",
        RefAct::SetDefault => "set_default",
        RefAct::Cascade => "cascade",
        RefAct::Restrict => "restrict",
        RefAct::NoAction => "no_action",
    }
}

fn insert_string(properties: &mut BTreeMap<String, MetadataValue>, key: &str, value: &str) {
    properties.insert(key.to_owned(), MetadataValue::String(value.to_owned()));
}

fn name(value: &Name<'_>) -> String {
    dequote_identifier(value.0)
}

fn dequote_identifier(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() < 2 {
        return value.to_owned();
    }
    match (bytes[0], bytes[bytes.len() - 1]) {
        (b'"', b'"') => value[1..value.len() - 1].replace("\"\"", "\""),
        (b'`', b'`') => value[1..value.len() - 1].replace("``", "`"),
        (b'[', b']') => value[1..value.len() - 1].replace("]]", "]"),
        (b'\'', b'\'') => value[1..value.len() - 1].replace("''", "'"),
        _ => value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_table_constraints_generated_columns_and_flags() {
        let table = parse_table_definition(
            r#"
            CREATE TABLE "orders" (
                id INTEGER CONSTRAINT pk_orders PRIMARY KEY AUTOINCREMENT,
                code TEXT COLLATE NOCASE CONSTRAINT uq_orders_code UNIQUE,
                total INTEGER CONSTRAINT ck_total CHECK (total >= 0),
                taxed INTEGER GENERATED ALWAYS AS (total + 10) STORED,
                user_id INTEGER,
                CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
                CONSTRAINT ck_pair CHECK (taxed >= total)
            ) STRICT
            "#,
        )
        .unwrap();

        assert!(table.strict);
        assert_eq!(table.name, "orders");
        assert_eq!(
            table.columns[3].generated_expression.as_deref(),
            Some("total + 10")
        );
        assert_eq!(
            table.columns[3].generated_storage.as_deref(),
            Some("STORED")
        );
        assert_eq!(table.columns[1].collation.as_deref(), Some("NOCASE"));
        assert_eq!(
            table
                .constraints
                .iter()
                .filter(|constraint| constraint.kind == ParsedConstraintKind::Check)
                .count(),
            2
        );
        let foreign_key = table
            .constraints
            .iter()
            .find(|constraint| constraint.kind == ParsedConstraintKind::ForeignKey)
            .unwrap();
        assert_eq!(foreign_key.name.as_deref(), Some("fk_user"));
        assert_eq!(foreign_key.referenced_table.as_deref(), Some("users"));
        assert_eq!(
            foreign_key.properties["on_delete"],
            MetadataValue::String("cascade".to_owned())
        );
    }

    #[test]
    fn parses_expression_and_partial_index() {
        let index = parse_index_definition(
            "CREATE UNIQUE INDEX idx_search ON users(lower(email) DESC, tenant_id) WHERE active = 1",
        )
        .unwrap();

        assert!(index.unique);
        assert_eq!(index.terms[0].expression, "lower (email)");
        assert_eq!(index.terms[0].column_name, None);
        assert_eq!(index.terms[0].order.as_deref(), Some("DESC"));
        assert_eq!(index.terms[0].nulls, None);
        assert_eq!(index.terms[1].column_name.as_deref(), Some("tenant_id"));
        assert_eq!(index.predicate.as_deref(), Some("active = 1"));
    }

    #[test]
    fn parses_trigger_without_token_guessing() {
        let trigger = parse_trigger_definition(
            r#"CREATE TRIGGER "trg orders" INSTEAD OF UPDATE OF total, tax ON order_view
               WHEN NEW.total >= 0 BEGIN SELECT NEW.total; END"#,
        )
        .unwrap();

        assert_eq!(trigger.name, "trg orders");
        assert_eq!(trigger.owner_name, "order_view");
        assert_eq!(trigger.timing, "INSTEAD OF");
        assert_eq!(trigger.event, "UPDATE");
        assert_eq!(trigger.update_columns, vec!["total", "tax"]);
        assert_eq!(trigger.when_expression.as_deref(), Some("NEW.total >= 0"));
    }

    #[test]
    fn schema_ddl_validator_accepts_schema_changes_and_rejects_row_access() {
        let accepted = validate_schema_ddl(
            "BEGIN; CREATE TABLE users(id INTEGER); ALTER TABLE users ADD COLUMN email TEXT; COMMIT;",
        )
        .unwrap();
        assert_eq!(accepted, 4);

        assert!(validate_schema_ddl(
            "CREATE TABLE users(id INTEGER); INSERT INTO users VALUES (1);"
        )
        .unwrap_err()
        .contains("INSERT"));
        assert!(
            validate_schema_ddl("CREATE TABLE copy AS SELECT * FROM users;")
                .unwrap_err()
                .contains("AS SELECT")
        );
        assert!(
            validate_schema_ddl("CREATE VIRTUAL TABLE docs USING fts5(body);")
                .unwrap_err()
                .contains("VIRTUAL TABLE")
        );
    }
}
