import { ManagementClient } from 'auth0';
import dotenv from 'dotenv';
import fetch from 'node-fetch';

dotenv.config();

async function initializeAuth0Client() {
  try {
    console.log('Attempting to get access token...');
    const tokenUrl = `https://${process.env.AUTH0_DOMAIN}/oauth/token`;
    console.log('Token URL:', tokenUrl);

    const tokenBody = {
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
      grant_type: 'client_credentials',
      scope: 'read:resource_servers update:resource_servers read:roles create:roles update:roles read:role_members create:role_members'
    };

    console.log('Request body:', JSON.stringify(tokenBody, null, 2));

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(tokenBody)
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Token request failed:', data);
      throw new Error(`Failed to get token: ${data.error_description || data.error || 'Unknown error'}`);
    }

    if (!data.access_token) {
      console.error('Token response:', data);
      throw new Error('No access token in response');
    }

    console.log('Successfully obtained access token');

    const client = new ManagementClient({
      domain: process.env.AUTH0_DOMAIN,
      token: data.access_token
    });

    return client;
  } catch (error) {
    console.error('Failed to initialize Auth0 client:', error);
    throw error;
  }
}

const permissions = [
  // Case Management
  {
    name: 'case:read',
    description: 'View case details, dockets, and non-sealed documents'
  },
  {
    name: 'case:create',
    description: 'Initialize new cases and add initial case information'
  },
  {
    name: 'case:update',
    description: 'Modify case details, status, and related information'
  },
  {
    name: 'case:seal',
    description: 'Apply restrictions to case access and visibility'
  },
  {
    name: 'case:assign',
    description: 'Assign or transfer cases between courts/judges'
  },

  // Document Operations
  {
    name: 'document:file',
    description: 'Submit new documents to case dockets'
  },
  {
    name: 'document:read',
    description: 'Access and view filed documents'
  },
  {
    name: 'document:seal',
    description: 'Restrict access to sensitive documents'
  },
  {
    name: 'document:serve',
    description: 'Process and confirm service of documents'
  },

  // Orders & Rulings
  {
    name: 'order:create',
    description: 'Draft and submit court orders'
  },
  {
    name: 'order:sign',
    description: 'Officially sign and enter court orders'
  },
  {
    name: 'judgment:enter',
    description: 'Enter final judgments and decisions'
  },

  // Administration
  {
    name: 'admin:users',
    description: 'Manage user accounts and access levels'
  },
  {
    name: 'admin:court',
    description: 'Configure court settings and operational parameters'
  },
  {
    name: 'admin:reports',
    description: 'Generate and access system reports'
  },

  // Financial
  {
    name: 'payment:process',
    description: 'Handle filing fees and payment processing'
  },
  {
    name: 'fee:waiver',
    description: 'Review and process fee waiver requests'
  }
];

async function createPermissions(auth0) {
  try {
    console.log('Starting permission creation...');

    // Get existing resource server
    const resourceServer = await auth0.resourceServers.get({ id: process.env.AUTH0_API_ID });
    console.log('Found resource server:', resourceServer);

    const existingScopes = new Set(resourceServer.scopes?.map(s => s.value));

    // Filter out permissions that already exist
    const newPermissions = permissions.filter(p => !existingScopes.has(p.name));

    if (newPermissions.length === 0) {
      console.log('All permissions already exist.');
      return;
    }

    // Format permissions for Auth0
    const formattedPermissions = newPermissions.map(p => ({
      value: p.name,
      description: p.description
    }));

    // Update API with new permissions
    await auth0.resourceServers.update(
      { id: process.env.AUTH0_API_ID },
      {
        scopes: [
          ...(resourceServer.scopes || []),
          ...formattedPermissions
        ]
      }
    );

    console.log(`Successfully created ${newPermissions.length} new permissions.`);
  } catch (error) {
    console.error('Error creating permissions:', error);
    console.error('Error details:', error.message);
    throw error;
  }
}

async function createRoles(auth0) {
  const roles = [
    {
      name: 'Judge',
      description: 'Judicial officer with full case management capabilities',
      permissions: [
        'case:read', 'case:update', 'case:seal', 'case:assign',
        'document:read', 'document:seal',
        'order:create', 'order:sign', 'judgment:enter'
      ]
    },
    {
      name: 'Attorney',
      description: 'Licensed attorney for case filing and management',
      permissions: [
        'case:read', 'case:create',
        'document:file', 'document:read', 'document:serve'
      ]
    },
    {
      name: 'Court Staff',
      description: 'Administrative court personnel',
      permissions: [
        'case:read', 'document:read',
        'payment:process', 'fee:waiver'
      ]
    }
  ];

  for (const role of roles) {
    try {
      // Check if role exists
      const existingRoles = await auth0.roles.getAll({
        name_filter: role.name
      });

      let roleId;

      if (existingRoles.length > 0) {
        console.log(`Role ${role.name} already exists`);
        roleId = existingRoles[0].id;
      } else {
        // Create role
        const createdRole = await auth0.roles.create({
          name: role.name,
          description: role.description
        });
        roleId = createdRole.id;
        console.log(`Created role: ${role.name}`);
      }

      // Assign permissions to role using correct method
      await auth0.roles.addPermissions(roleId, {
        permissions: role.permissions.map(p => ({
          permission_name: p,
          resource_server_identifier: process.env.AUTH0_API_ID
        }))
      });

      console.log(`Assigned permissions to role: ${role.name}`);
    } catch (error) {
      console.error(`Error handling role ${role.name}:`, error.message);
      console.error('Full error:', error);
    }
  }
}

async function createClientGrant(auth0) {
  try {
    await auth0.clientGrants.create({
      client_id: process.env.AUTH0_CLIENT_ID,
      audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
      scope: [
        'read:resource_servers',
        'update:resource_servers',
        'read:roles',
        'create:roles',
        'update:roles',
        'read:role_members',
        'create:role_members'
      ]
    });
    console.log('Client grant created successfully');
  } catch (error) {
    if (error.message.includes('grant already exists')) {
      console.log('Client grant already exists');
    } else {
      console.error('Error creating client grant:', error.message);
    }
  }
}

async function createResourceServer(auth0) {
  try {
    console.log('Creating resource server...');

    const apiConfig = {
      name: 'Lexodus Court Filing API',
      identifier: process.env.AUTH0_API_ID, // This should be your API identifier like 'https://api.lexodus.courts.gov'
      signing_alg: 'RS256',
      token_lifetime: 86400,
      scopes: [] // We'll add scopes later
    };

    try {
      const existingApi = await auth0.resourceServers.get({ id: process.env.AUTH0_API_ID });
      console.log('Resource server already exists');
      return existingApi;
    } catch (error) {
      if (error.statusCode === 404) {
        const createdApi = await auth0.resourceServers.create(apiConfig);
        console.log('Resource server created successfully');
        return createdApi;
      }
      throw error;
    }
  } catch (error) {
    console.error('Error creating resource server:', error);
    throw error;
  }
}


async function verifyRolePermissions(auth0, roleName) {
  try {
    // Get all roles
    const { data: allRoles } = await auth0.roles.getAll();
    const role = allRoles.find(r => r.name === roleName);

    if (!role) {
      console.log(`Role ${roleName} not found`);
      return;
    }

    console.log(`Found role ${roleName} with ID: ${role.id}`);

    try {
      const { data: permissions } = await auth0.roles.getPermissions({ id: role.id });

      console.log(`\nPermissions for ${roleName}:`);
      if (permissions && permissions.length > 0) {
        permissions.forEach(p => {
          console.log(`- ${p.permission_name}`);
        });
      } else {
        console.log('No permissions assigned');
      }

      return permissions;
    } catch (permError) {
      console.error(`Error getting permissions for role ${roleName}:`, permError.message);
    }
  } catch (error) {
    console.error(`Error verifying permissions for ${roleName}:`, error.message);
    if (error.data) {
      console.error('Error data:', error.data);
    }
    return null;
  }
}

async function updateRolePermissions(auth0, roleName, permissions) {
  try {
    console.log(`\nUpdating permissions for ${roleName}...`);

    // Get role ID
    const { data: roles } = await auth0.roles.getAll();
    const role = roles.find(r => r.name === roleName);

    if (!role) {
      console.log(`Role ${roleName} not found`);
      return;
    }

    console.log(`Found role ${roleName} with ID: ${role.id}`);

    try {
      // The proper payload structure for Auth0
      const payload = {
        permissions: permissions.map(p => ({
          permission_name: p,
          resource_server_identifier: process.env.AUTH0_API_ID
        }))
      };

      // Add permissions with correct method structure
      await auth0.roles.addPermissions({ id: role.id }, payload);
      console.log(`Successfully added permissions to ${roleName}`);

      // Verify the update
      const { data: updatedPermissions } = await auth0.roles.getPermissions({ id: role.id });
      if (updatedPermissions && updatedPermissions.length > 0) {
        console.log(`\nNew permissions for ${roleName}:`);
        updatedPermissions.forEach(p => {
          console.log(`- ${p.permission_name}`);
        });
      } else {
        console.log(`No permissions found for ${roleName} after update`);
      }
    } catch (permError) {
      console.error(`Error updating permissions:`, permError);
      throw permError;
    }
  } catch (error) {
    console.error(`Error updating permissions for ${roleName}:`, error.message);
  }
}
async function main() {
  try {
    const auth0 = await initializeAuth0Client();
    console.log('Auth0 client initialized successfully');

    console.log('\n1. Setting up Resource Server...');
    await createResourceServer(auth0);

    console.log('\n2. Creating Permissions...');
    await createPermissions(auth0);

    console.log('\n3. Updating Role Permissions...');
    const judgePermissions = [
      'case:read', 'case:update', 'case:seal', 'case:assign',
      'document:read', 'document:seal', 'document:serve',
      'order:create', 'order:sign', 'judgment:enter',
      'admin:reports', 'admin:court'
    ];

    const attorneyPermissions = [
      'case:read', 'case:create',
      'document:file', 'document:read', 'document:serve'
    ];

    const staffPermissions = [
      'case:read', 'document:read',
      'payment:process', 'fee:waiver'
    ];

    console.log('\nUpdating Judge permissions...');
    await updateRolePermissions(auth0, 'Judge', judgePermissions);

    console.log('\nUpdating Attorney permissions...');
    await updateRolePermissions(auth0, 'Attorney', attorneyPermissions);

    console.log('\nUpdating Court Staff permissions...');
    await updateRolePermissions(auth0, 'Court Staff', staffPermissions);

    console.log('\n4. Final Verification...');
    await verifyRolePermissions(auth0, 'Judge');
    await verifyRolePermissions(auth0, 'Attorney');
    await verifyRolePermissions(auth0, 'Court Staff');
  } catch (error) {
    console.error('Script failed:', error.message);
    process.exit(1);
  }
}

main();
