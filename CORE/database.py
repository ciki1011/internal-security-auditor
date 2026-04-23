from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

# URL za Postgres (zameni sa svojim kredencijalima ako su drugačiji)
# Format: postgresql+asyncpg://user:password@host:port/dbname
DATABASE_URL = "postgresql+asyncpg://postgres:admin@localhost:5432/auditor_db"

# Pravimo asinhroni motor
engine = create_async_engine(DATABASE_URL, echo=True)

# Pravimo fabriku sesija (konekcija)
SessionLocal = async_sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

# Osnovna klasa koju će svi modeli (tabele) nasleđivati
class Base(DeclarativeBase):
    pass

# Funkcija koju ćemo koristiti u API rutama za pristup bazi
async def get_db():
    async with SessionLocal() as session:
        yield session