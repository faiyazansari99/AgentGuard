from alembic import op
import sqlalchemy as sa
revision='0003_enterprise_fields'; down_revision='0002_audit_hash'; branch_labels=None; depends_on=None

def upgrade():
    op.add_column('users', sa.Column('mfa_secret',sa.String(64),nullable=True))
    op.add_column('api_keys', sa.Column('scopes',sa.Text(),nullable=True,server_default='gateway:check'))
    op.create_table('integrations',sa.Column('id',sa.String(32),primary_key=True),sa.Column('provider',sa.String(64)),sa.Column('status',sa.String(32)),sa.Column('org_id',sa.String(32)),sa.Column('external_account',sa.String(320)),sa.Column('token_ciphertext',sa.Text()),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_integrations_org_id','integrations',['org_id'])

def downgrade():
    op.drop_index('ix_integrations_org_id',table_name='integrations'); op.drop_table('integrations'); op.drop_column('api_keys','scopes'); op.drop_column('users','mfa_secret')
