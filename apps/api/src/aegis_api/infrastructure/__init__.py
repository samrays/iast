"""Infrastructure layer — adapters implementing the domain's ports.

SQLAlchemy repositories, the Argon2 hasher, the JWT codec, the TOTP service and the
Fernet-based secret cipher live here. Nothing in this layer defines business rules; if a
rule appears here, it belongs in ``domain`` or ``application`` instead.
"""
