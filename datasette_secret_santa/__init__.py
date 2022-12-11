from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datasette import hookimpl, Response
import pathlib
import random
import textwrap

words = (pathlib.Path(__file__).parent / "words.txt").read_text().splitlines()


async def _error(datasette, request, message, status=400):
    return Response.html(
        await datasette.render_template(
            "secret_santa_error.html",
            {
                "message": message,
            },
            request=request,
        ),
        status=status,
    )


@hookimpl
def startup(datasette):
    async def init():
        try:
            db = datasette.get_database("santa")
        except KeyError:
            assert False, "datasette-secret-santa plugin requires santa.db database"
        await db.execute_write_script(
            textwrap.dedent(
                """
            create table if not exists secret_santa (
                slug text primary key,
                name text
            );
            create table if not exists secret_santa_participants (
                id integer primary key,
                slug text references secret_santa(slug),
                name text,
                secret_message_encrypted bytes,
                password_issued_at text,
                public_key text,
                private_key text,
                message_read_at text
            );
        """
            )
        )

    return init


async def redirect_to_home(request):
    return Response.redirect("/")


async def secret_santa(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    if santa is None:
        return await _error(
            datasette, request, "Could not find secret santa", status=404
        )
    participants = [
        dict(r)
        for r in (
            await db.execute(
                "select * from secret_santa_participants where slug = ?", [slug]
            )
        ).rows
    ]
    return Response.html(
        await datasette.render_template(
            "secret_santa.html",
            {
                "slug": slug,
                "santa": santa,
                "participants": participants,
                "is_ready": participants
                and all(
                    p["password_issued_at"] and not p["secret_message_encrypted"]
                    for p in participants
                ),
                "is_done": participants
                and all(p["secret_message_encrypted"] for p in participants),
            },
            request=request,
        )
    )


async def add_participant(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    data = await request.post_vars()
    name = data.get("name", "").strip()
    if not name:
        return await _error(datasette, request, "Please provide a name", status=400)
    if santa is None:
        return await _error(
            datasette, request, "Could not find secret santa", status=404
        )
    # Add the new participant
    await db.execute_write(
        "insert into secret_santa_participants (slug, name) values (:slug, :name)",
        {
            "slug": slug,
            "name": name,
        },
    )
    # Redirect to the secret santa page
    return Response.redirect(f"/secret-santa/{slug}")


async def set_password(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    if santa is None:
        return await _error(
            datasette, request, "Could not find secret santa", status=404
        )
    participant_id = request.url_vars["id"]
    participant = (
        await db.execute(
            "select * from secret_santa_participants where id = ? and slug = ?",
            [participant_id, slug],
        )
    ).first()
    if participant is None:
        return await _error(
            datasette, request, "Could not find participant", status=404
        )
    if request.method.lower() != "post":
        return Response.html(
            await datasette.render_template(
                "santa_set_password.html",
                {"santa": santa, "participant": participant},
                request=request,
            )
        )
    else:
        # Generate password, and public/private key pair, and save it
        password = await generate_password_and_keys_for_user(db, participant_id)
        return Response.html(
            await datasette.render_template(
                "santa_set_password.html",
                {"santa": santa, "participant": participant, "password": password},
                request=request,
            )
        )


async def reveal(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    if santa is None:
        return await _error(
            datasette, request, "Could not find secret santa", status=404
        )
    participant_id = request.url_vars["id"]
    participant = (
        await db.execute(
            "select * from secret_santa_participants where id = ? and slug = ?",
            [participant_id, slug],
        )
    ).first()
    if participant is None:
        return await _error(
            datasette, request, "Could not find participant", status=404
        )
    if not participant["secret_message_encrypted"]:
        return await _error(
            datasette, request, "Secret message not available yet", status=404
        )

    if request.method.lower() != "post":
        return Response.html(
            await datasette.render_template(
                "santa_reveal.html",
                {"santa": santa, "participant": participant},
                request=request,
            )
        )
    else:
        data = await request.post_vars()
        password = data.get("password", "").strip()
        if not password:
            return await _error(
                datasette, request, "Please provide a password", status=400
            )
        # Decrypt the private key with the password
        try:
            private_key = decrypt_private_key_for_user(participant, password)
        except ValueError:
            return await _error(datasette, request, "Incorrect password", status=400)
        # Decrypt the secret message with the private key
        decrypted_message = private_key.decrypt(
            participant["secret_message_encrypted"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ).decode("utf-8")
        await db.execute_write(
            "update secret_santa_participants set message_read_at = datetime('now') where id = ?",
            [participant_id],
        )
        return Response.html(
            await datasette.render_template(
                "santa_reveal.html",
                {
                    "santa": santa,
                    "participant": participant,
                    "message": decrypted_message,
                },
                request=request,
            )
        )


def decrypt_private_key_for_user(participant, password):
    return serialization.load_pem_private_key(
        participant["private_key"].encode("utf-8"),
        password=password.encode("utf-8"),
        backend=default_backend(),
    )


async def generate_password_and_keys_for_user(db, participant_id):
    password = " ".join(random.sample(words, 3))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize the keys for storage or transmission
    private_key_serialized = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    ).decode("utf-8")
    public_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    await db.execute_write(
        """
        update secret_santa_participants
        set
            password_issued_at = datetime('now'),
            public_key = :public_key,
            private_key = :private_key
        where id = :id
        """,
        {
            "id": participant_id,
            "public_key": public_key_serialized,
            "private_key": private_key_serialized,
        },
    )
    return password


async def assign_participants(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    if santa is None:
        return await _error(
            datasette, request, "Could not find secret santa", status=404
        )
    participants = [
        dict(r)
        for r in (
            await db.execute(
                "select * from secret_santa_participants where slug = ?", [slug]
            )
        ).rows
    ]
    if any(p["password_issued_at"] is None for p in participants):
        return await _error(
            datasette,
            request,
            "All participants must have a password before assigning",
            status=400,
        )
    if request.method.lower() != "post":
        return await _error(datasette, request, "POST required", status=405)
    else:
        # Assign participants
        random.shuffle(participants)
        for i, participant in enumerate(participants):
            assigned = participants[(i + 1) % len(participants)]
            message = "You should buy a gift for {}".format(assigned["name"])
            # Encrypt the message with their public key
            public_key = serialization.load_pem_public_key(
                participant["public_key"].encode("utf-8"), backend=default_backend()
            )
            secret_message_encrypted = public_key.encrypt(
                message.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            await db.execute_write(
                """
                update secret_santa_participants
                set secret_message_encrypted = :secret_message_encrypted
                where id = :id
                """,
                {
                    "id": participant["id"],
                    "secret_message_encrypted": secret_message_encrypted,
                },
            )
        return Response.redirect(f"/secret-santa/{slug}")


@hookimpl
def canned_queries(datasette, database):
    if database == "santa":
        return {
            "create_secret_santa": {
                "sql": "insert into secret_santa (slug, name) values (:slug, :name)",
                "write": True,
            }
        }


@hookimpl
def register_routes():
    return [
        (r"^/secret-santa/(?P<slug>[^/]+)$", secret_santa),
        (r"^/secret-santa/(?P<slug>[^/]+)/add$", add_participant),
        (r"^/secret-santa/(?P<slug>[^/]+)/assign$", assign_participants),
        (r"^/secret-santa/(?P<slug>[^/]+)/set-password/(?P<id>\d+)$", set_password),
        (r"^/secret-santa/(?P<slug>[^/]+)/reveal/(?P<id>\d+)$", reveal),
        (r"^/secret-santa/?$", redirect_to_home),
    ]


@hookimpl
def extra_template_vars(datasette, view_name):
    async def secret_santa_index():
        if view_name == "index":
            db = datasette.get_database("santa")
            return {
                "secret_santas": [
                    dict(r)
                    for r in (
                        await db.execute(
                            "select * from secret_santa order by rowid desc"
                        )
                    )
                ]
            }
        return {}

    return secret_santa_index
