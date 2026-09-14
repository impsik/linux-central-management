"""One-time host enrollment credentials."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '20260914_00'
down_revision = '20260710_00'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('host_enrollments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('agent_id', sa.String(), nullable=False, unique=True),
        sa.Column('created_by', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True)))


def downgrade():
    op.drop_table('host_enrollments')
