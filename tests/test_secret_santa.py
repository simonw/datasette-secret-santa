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


@pytest.mark.asyncio
async def test_full_flow(ds):
    db = ds.get_database("santa")
    tables = await db.table_names()
    assert tables == ["secret_santa", "secret_santa_participants"]
    assert (await ds.client.get("/secret-santa/demo")).status_code == 404
    await db.execute_write(
        "insert into secret_santa (slug, name) values (?, ?)",
        ["demo", "Demo secret santa"],
    )
    response1 = await ds.client.get("/secret-santa/demo")
    assert response1.status_code == 200
    assert "Demo secret santa" in response1.text
    csrftoken = response1.cookies["ds_csrftoken"]

    # Now add some participants
    for i in range(1, 5):
        post_response = await ds.client.post(
            "/secret-santa/demo/add",
            data={"name": f"person-{i}", "csrftoken": csrftoken},
        )
        assert post_response.status_code == 302
        assert post_response.headers["location"] == "/secret-santa/demo"

    assign_button = '<input type="submit" value="Assign recipients!">'

    # Participants should now be listed
    response2 = await ds.client.get("/secret-santa/demo")
    assert response2.status_code == 200
    for i in range(1, 5):
        assert f"person-{i}" in response2.text
    assert assign_button not in response2.text

    # But should not have public/private keys
    for row in await db.execute("select * from secret_santa_participants"):
        assert not row["public_key"]
        assert not row["private_key"]

    # Each user now sets their password
    participant_passwords = {}
    for row in await db.execute("select * from secret_santa_participants"):
        id = row["id"]
        response3 = await ds.client.get(f"/secret-santa/demo/set-password/{id}")
        assert response3.status_code == 200
        assert f"click this button if you are {row['name']}" in response3.text
        set_password_response = await ds.client.post(
            f"/secret-santa/demo/set-password/{id}",
            data={"csrftoken": csrftoken},
        )
        assert set_password_response.status_code == 200
        assert "Your secret password is" in set_password_response.text
        password = set_password_response.text.split(' class="your-password">')[1].split(
            "<"
        )[0]
        participant_passwords[id] = (row["name"], password)

    # OK, at this point everyone should have a public/private key in the DB
    for row in await db.execute("select * from secret_santa_participants"):
        assert row["public_key"]
        assert row["private_key"]
        # But not a message
        assert not row["secret_message_encrypted"]

    # Now we can generate the secret santa
    response4 = await ds.client.get("/secret-santa/demo")
    assert assign_button in response4.text

    # Click that assign button
    assign_response = await ds.client.post(
        "/secret-santa/demo/assign",
        data={"csrftoken": csrftoken},
    )
    assert assign_response.status_code == 302
    assert assign_response.headers["location"] == "/secret-santa/demo"

    # Now everyone should have a message
    for row in await db.execute("select * from secret_santa_participants"):
        assert row["secret_message_encrypted"]
        assert not row["message_read_at"]

    # Use their passwords to decrypt their messages
    recipients = set()
    for id, (name, password) in participant_passwords.items():
        decrypt_response = await ds.client.post(
            f"/secret-santa/demo/reveal/{id}",
            data={"password": password, "csrftoken": csrftoken},
        )
        assert decrypt_response.status_code == 200
        secret_message = decrypt_response.text.split(' class="secret-message">')[
            1
        ].split("<")[0]
        assert secret_message.startswith("You should buy a gift for ")
        recipient = secret_message.split()[-1]
        # Should not be buying a gift for themselves
        assert name != recipient
        recipients.add(recipient)

    # Everyone should be a recipient
    assert len(recipients) == len(participant_passwords)

    # Now everyone should have a message
    for row in await db.execute("select * from secret_santa_participants"):
        assert row["message_read_at"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ("/secret-santa", "/secret-santa/"))
async def test_redirects(ds, path):
    response = await ds.client.get(path)
    assert response.status_code == 302
    assert response.headers["location"] == "/"


@pytest.mark.asyncio
async def test_create_group_from_homepage(ds):
    response1 = await ds.client.get("/")
    assert response1.status_code == 200
    assert '<a href="/santa/create_secret_santa">create one here' in response1.text
    assert (await ds.client.get("/secret-santa/test")).status_code == 404
    response2 = await ds.client.get("/santa/create_secret_santa")
    csrftoken = response2.cookies["ds_csrftoken"]
    post_response = await ds.client.post(
        "/santa/create_secret_santa",
        data={"slug": "test", "name": "Test group", "csrftoken": csrftoken},
    )
    assert post_response.status_code == 302
    assert (await ds.client.get("/secret-santa/test")).status_code == 200
