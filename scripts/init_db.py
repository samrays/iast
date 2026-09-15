"""Initialize SQLite database schema and seed the Owner account."""

import asyncio
from uuid import uuid4
from datetime import datetime, timezone

from aegis_api.config import get_settings
from aegis_api.container import build_container
from aegis_api.infrastructure.db.models import Base
from aegis_api.operations import seed_organization
from aegis_api.domain.entities import LicenseTier


async def main() -> None:
    container = build_container(get_settings())
    
    # 1. Create tables
    async with container.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables created successfully.")

    # 2. Seed owner account if not present
    try:
        res = await seed_organization(
            container,
            organization="Aegis Demo Corp",
            email="owner@aegis.example",
            password="2yjIzhY1m2IzWJc2fEx$&0M$",
            full_name="Platform Owner",
            tier=LicenseTier.ENTERPRISE,
        )
        print(f"Seeded Owner: {res.email} password: 2yjIzhY1m2IzWJc2fEx$&0M$")
    except Exception as e:
        print(f"Seed note: {e}")

    await container.aclose()


if __name__ == "__main__":
    asyncio.run(main())
