from alembic import op
import sqlalchemy as sa
revision='0002_audit_hash'; down_revision='0001_initial'; branch_labels=None; depends_on=None

def upgrade():
    op.add_column('audit', sa.Column('integrity_hash',sa.String(64),nullable=True))

def downgrade(): op.drop_column('audit','integrity_hash')
