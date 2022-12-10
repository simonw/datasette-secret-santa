from datasette.app import Datasette
import pytest_asyncio
import pytest
import sqlite3


@pytest_asyncio.fixture
async def ds(tmpdir):
    db_path = str(tmpdir / "santa.db")
    conn = sqlite3.connect(db_path)
    conn.execute("vacuum")
    ds = Datasette([db_path])
    await ds.invoke_startup()
    return ds


@pytest.mark.asyncio
async def test_plugin_is_installed(ds):
    response = await ds.client.get("/-/plugins.json")
    assert response.status_code == 200
    installed_plugins = {p["name"] for p in response.json()}
    assert "datasette-secret-santa" in installed_plugins


@pytest.mark.asyncio
async def test_error_on_startup_if_no_santa_database():
    ds = Datasette([])
    with pytest.raises(AssertionError) as ex:
        await ds.invoke_startup()
        assert ex.value == "datasette-secret-santa plugin requires santa.db database"
