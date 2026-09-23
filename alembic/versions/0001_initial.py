from alembic import op
import sqlalchemy as sa
revision='0001_initial'; down_revision=None; branch_labels=None; depends_on=None

def upgrade():
    op.create_table('users', sa.Column('id',sa.String(32),primary_key=True), sa.Column('email',sa.String(320),nullable=False), sa.Column('password_hash',sa.String(512),nullable=False), sa.Column('role',sa.String(32),nullable=False), sa.Column('org_id',sa.String(32),nullable=False), sa.Column('mfa_enabled',sa.Boolean(),nullable=False), sa.Column('created_at',sa.DateTime(timezone=True)))
    op.create_index('ix_users_email','users',['email'],unique=True); op.create_index('ix_users_org_id','users',['org_id'])
    op.create_table('agents',sa.Column('id',sa.String(32),primary_key=True),sa.Column('name',sa.String(200)),sa.Column('model',sa.String(200)),sa.Column('status',sa.String(32)),sa.Column('risk',sa.Integer()),sa.Column('owner',sa.String(200)),sa.Column('org_id',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_agents_org_id','agents',['org_id'])
    op.create_table('policies',sa.Column('id',sa.String(32),primary_key=True),sa.Column('name',sa.String(200)),sa.Column('action',sa.String(200)),sa.Column('resource',sa.String(500)),sa.Column('effect',sa.String(32)),sa.Column('threshold',sa.Float()),sa.Column('org_id',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_policies_org_id','policies',['org_id'])
    op.create_table('audit',sa.Column('id',sa.Integer(),primary_key=True),sa.Column('actor',sa.String(32)),sa.Column('agent',sa.String(32)),sa.Column('action',sa.String(200)),sa.Column('decision',sa.String(64)),sa.Column('details',sa.Text()),sa.Column('org_id',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_audit_org_id','audit',['org_id'])
    op.create_table('approvals',sa.Column('id',sa.String(32),primary_key=True),sa.Column('agent',sa.String(32)),sa.Column('action',sa.String(200)),sa.Column('amount',sa.Float()),sa.Column('status',sa.String(32)),sa.Column('requested_by',sa.String(32)),sa.Column('org_id',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_approvals_org_id','approvals',['org_id'])
    op.create_table('api_keys',sa.Column('id',sa.String(32),primary_key=True),sa.Column('name',sa.String(200)),sa.Column('key_hash',sa.String(64)),sa.Column('status',sa.String(32)),sa.Column('scopes',sa.Text()),sa.Column('last_used',sa.DateTime(timezone=True)),sa.Column('org_id',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_api_keys_key_hash','api_keys',['key_hash']); op.create_index('ix_api_keys_org_id','api_keys',['org_id'])
    op.create_table('incidents',sa.Column('id',sa.String(32),primary_key=True),sa.Column('severity',sa.String(32)),sa.Column('title',sa.String(300)),sa.Column('status',sa.String(32)),sa.Column('agent',sa.String(32)),sa.Column('org_id',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True))); op.create_index('ix_incidents_org_id','incidents',['org_id'])

def downgrade():
    for t in ['incidents','api_keys','approvals','audit','policies','agents','users']: op.drop_table(t)
