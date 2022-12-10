from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from datasette import hookimpl, Response
import hashlib
import os
import pathlib
import random
import textwrap

words = (pathlib.Path(__file__).parent / "words.txt").read_text().splitlines()


@hookimpl
def startup(datasette):
    async def init():
        db = datasette.get_database("santa")
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
                password_salt bytes,
                public_key text,
                private_key_encrypted_iv bytes,
                private_key_encrypted_ct bytes,
                message_read_at text
            );
        """
            )
        )

    return init


async def index(request):
    return Response.html("List of secret santas goes here")


async def secret_santa(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    if santa is None:
        return Response.html("Could not find secret santa", status=404)
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
                and all(p["password_issued_at"] and not p["secret_message_encrypted"] for p in participants),
                "is_done": participants and all(p["secret_message_encrypted"] for p in participants),
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
        return Response.html("Please provide a name", status=400)
    if santa is None:
        return Response.html("Could not find secret santa", status=404)
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
        return Response.html("Could not find secret santa", status=404)
    participant_id = request.url_vars["id"]
    participant = (
        await db.execute(
            "select * from secret_santa_participants where id = ? and slug = ?",
            [participant_id, slug],
        )
    ).first()
    if participant is None:
        return Response.html("Could not find participant", status=404)
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
        return Response.html("Could not find secret santa", status=404)
    participant_id = request.url_vars["id"]
    participant = (
        await db.execute(
            "select * from secret_santa_participants where id = ? and slug = ?",
            [participant_id, slug],
        )
    ).first()
    if participant is None:
        return Response.html("Could not find participant", status=404)
    if not participant["secret_message_encrypted"]:
        return Response.html("No secret message yet", status=404)
    
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
            return Response.html("Please provide a password", status=400)
        # Decrypt the private key with the password
        private_key = decrypt_private_key_for_user(participant, password)
        if private_key is None:
            return Response.html("Incorrect password", status=400)
        # Decrypt the secret message with the private key
        decrypted_message = private_key.decrypt(
            participant["secret_message_encrypted"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode("utf-8")
        return Response.html(
            await datasette.render_template(
                "santa_reveal.html",
                {"santa": santa, "participant": participant, "message": decrypted_message},
                request=request,
            )
        )


def decrypt_private_key_for_user(participant, password):
    # Decrypt the private key with the password
    password_sha256 = hashlib.sha256(password.encode("utf-8")).digest()
    iv = participant["private_key_encrypted_iv"]
    ct = participant["private_key_encrypted_ct"]
    cipher = Cipher(algorithms.AES(password_sha256), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    private_key_raw = decryptor.update(ct) + decryptor.finalize()
    return serialization.load_pem_private_key(
        private_key_raw,
        password=None,
        backend=default_backend()
    )


async def generate_password_and_keys_for_user(db, participant_id):
    password = " ".join(random.sample(words, 3))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize the keys for storage or transmission
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # We will save public key bytes, but we need to save encrypted private key bytes
    private_key_encrypted_iv, private_key_encrypted_ct = encrypt_message_symmetric_aes(
        password.encode("utf-8"), private_key_bytes
    )

    await db.execute_write(
        """
        update secret_santa_participants
        set
            password_issued_at = datetime('now'),
            -- password_salt = :password_salt,
            public_key = :public_key,
            private_key_encrypted_iv = :private_key_encrypted_iv,
            private_key_encrypted_ct = :private_key_encrypted_ct
        where id = :id
        """,
        {
            "id": participant_id,
            "password_salt": password.encode("utf-8"),
            "public_key": public_key_bytes,
            "private_key_encrypted_iv": private_key_encrypted_iv,
            "private_key_encrypted_ct": private_key_encrypted_ct,
        },
    )
    return password


def encrypt_message_symmetric_aes(secret_key, message):
    secret_key = hashlib.sha256(secret_key).digest()
    padder = PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    iv = os.urandom(16)  # generate random initialization vector
    cipher = Cipher(
        algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return (iv, ct)


async def assign_participants(request, datasette):
    slug = request.url_vars["slug"]
    db = datasette.get_database("santa")
    santa = (
        await db.execute("select * from secret_santa where slug = ?", [slug])
    ).first()
    if santa is None:
        return Response.html("Could not find secret santa", status=404)
    participants = [
        dict(r)
        for r in (
            await db.execute(
                "select * from secret_santa_participants where slug = ?", [slug]
            )
        ).rows
    ]
    if any(p["password_issued_at"] is None for p in participants):
        return Response.html("Not all participants have passwords set", status=400)
    if request.method.lower() != "post":
        return Response.html("Please use POST to assign participants", status=405)
    else:
        # Assign participants
        random.shuffle(participants)
        for i, participant in enumerate(participants):
            assigned = participants[(i + 1) % len(participants)]
            message = "You should buy a gift for {}".format(assigned["name"])
            # Encrypt the message with their public key
            public_key = serialization.load_pem_public_key(
                participant["public_key"],
                backend=default_backend()
            )
            secret_message_encrypted = public_key.encrypt(
                message.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
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
        (r"^/secret-santa$", index),
    ]
