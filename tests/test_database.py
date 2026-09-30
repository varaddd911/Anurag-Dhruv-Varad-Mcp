import os

import pytest

import database as dbmod
from errors import DataAccessViolationError


def test_seed_is_deterministic_and_idempotent(fresh_db):
    conn = dbmod.connect_admin(fresh_db)
    first = dbmod.table_counts(conn)
    dbmod.seed_database(conn)  # second seed must not duplicate rows
    assert dbmod.table_counts(conn) == first
    assert first["customers"] == 6 and first["loan_products"] == 7 and first["audit_log"] == 0
    assert conn.execute("SELECT full_name, kyc_status FROM customers WHERE customer_id='CUS-10042'").fetchone()[:] == ("Priya Sharma", "verified")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()


def test_missing_database_is_a_typed_error(tmp_path):
    with pytest.raises(dbmod.DatabaseNotInitialisedError):
        dbmod.connect_scoped("accounts_server", str(tmp_path / "nope.db"))


# The isolation matrix: every (server, table) pair outside the whitelist must be refused by SQLite itself.
ALL = set(dbmod.ALL_TABLES)
ALLOWED_READ = {server: set(perms) for server, perms in dbmod.SERVER_TABLE_PERMISSIONS.items()}


@pytest.mark.parametrize("server", list(dbmod.SERVER_TABLE_PERMISSIONS))
def test_server_can_read_only_its_own_tables(server):
    with dbmod.connect_scoped(server) as db:
        for table in ALL:
            if table in ALLOWED_READ[server]:
                db.query(f"SELECT COUNT(*) AS n FROM {table}")
            else:
                with pytest.raises(DataAccessViolationError) as exc:
                    db.query(f"SELECT COUNT(*) AS n FROM {table}")
                assert exc.value.details["table"] == table and exc.value.details["operation"] == "read"


def test_products_server_is_structurally_unable_to_read_customer_data():
    with dbmod.connect_scoped("products_server") as db:
        for sql in (
            "SELECT * FROM customers",
            "SELECT kyc_status FROM customers WHERE customer_id='CUS-10042'",
            "SELECT p.product_id FROM loan_products p JOIN customers c ON 1=1",   # sneaking it into a join
            "SELECT (SELECT COUNT(*) FROM accounts)",                              # or a sub-select
            "SELECT * FROM transactions",
            "SELECT * FROM audit_log",
        ):
            with pytest.raises(DataAccessViolationError):
                db.query(sql)


def test_write_permissions_are_per_table_and_per_operation():
    with dbmod.connect_scoped("accounts_server") as db:  # read-only server
        with pytest.raises(DataAccessViolationError):
            db.execute("UPDATE accounts SET balance = 0")
        with pytest.raises(DataAccessViolationError):
            db.execute("INSERT INTO audit_log(timestamp,action_type,performed_by,outcome,source_server) VALUES('t','A','b','SUCCESS','s')")
    with dbmod.connect_scoped("compliance_comms_server") as db:
        db.execute("INSERT INTO audit_log(timestamp,action_type,performed_by,outcome,source_server) VALUES('t','TEST_ACTION','tester','SUCCESS','s')")
        with pytest.raises(DataAccessViolationError):   # append-only audit log
            db.execute("DELETE FROM audit_log")
        with pytest.raises(DataAccessViolationError):
            db.execute("UPDATE audit_log SET outcome='FAILED'")
        with pytest.raises(DataAccessViolationError):   # cannot edit customer master data
            db.execute("UPDATE customers SET kyc_status='verified'")


def test_ddl_pragma_and_attach_are_denied_for_every_server(tmp_path):
    for server in dbmod.SERVER_TABLE_PERMISSIONS:
        with dbmod.connect_scoped(server) as db:
            for sql in ("CREATE TABLE evil(x)", "DROP TABLE loan_products", "PRAGMA foreign_keys=OFF",
                        f"ATTACH DATABASE '{(tmp_path / 'other.db').as_posix()}' AS other"):
                with pytest.raises(DataAccessViolationError):
                    db.execute(sql)


def test_transaction_rolls_back_on_error():
    with dbmod.connect_scoped("compliance_comms_server") as db:
        before = db.query_one("SELECT COUNT(*) AS n FROM audit_log")["n"]
        with pytest.raises(RuntimeError):
            with db.transaction():
                db.execute("INSERT INTO audit_log(timestamp,action_type,performed_by,outcome,source_server) VALUES('t','A','b','SUCCESS','s')")
                raise RuntimeError("simulated failure after the insert")
        assert db.query_one("SELECT COUNT(*) AS n FROM audit_log")["n"] == before


def test_cli_reset_and_seed(tmp_path, capsys):
    path = tmp_path / "cli.db"
    assert dbmod.main(["--seed", "--reset", "--path", str(path)]) == 0
    assert os.path.exists(path)
    assert '"customers": 6' in capsys.readouterr().out
