import url from 'url';

import {
  AdminFileToWrite,
  BaseGeneratedListTypes,
  KeystoneConfig,
  SerializedFieldMeta,
} from '@keystone-spike/types';
import { text, timestamp } from '@keystone-spike/fields';

import { getExtendGraphQLSchema } from './getExtendGraphQLSchema';
import { initFirstItemSchemaExtension } from './initFirstItemSchemaExtension';
import { AuthConfig, Auth, ResolvedAuthGqlNames } from './types';

import { signinTemplate } from './templates/signin';
import { initTemplate } from './templates/init';


/**
 * createAuth function
 *
 * Generates config for Keystone to implement standard auth features.
 */
export function createAuth<GeneratedListTypes extends BaseGeneratedListTypes>(
  config: AuthConfig<GeneratedListTypes>
): Auth {
  const gqlNames: ResolvedAuthGqlNames = {
    // TODO: The list should validate listKey uses CamelCase
    createInitialItem: `createInitial${config.listKey}`,
    authenticateItemWithPassword: `authenticate${config.listKey}WithPassword`,
    ItemAuthenticationWithPasswordResult: `${config.listKey}AuthenticationWithPasswordResult`,
    sendItemPasswordResetLink: `send${config.listKey}PasswordResetLink`,
    sendItemPasswordResetLinkResult: `send${config.listKey}PasswordResetLinkResult`,
    sendItemMagicAuthLink: `send${config.listKey}MagicAuthLink`,
    sendItemMagicAuthLinkResult: `send${config.listKey}MagicAuthLinkResult`,
  };

  // Fields added to the auth list
  const additionalListFields = {
    // TODO: Should these be named for `config.secretField`?
    // TODO: Add these to list in withAuth() and also return..
    [`${config.secretField}ResetToken`]: text({ access: () => false, isRequired: false }),
    [`${config.secretField}ResetIssuedAt`]: timestamp({ access: () => false, isRequired: false }),
    [`${config.secretField}ResetRedeemedAt`]: timestamp({ access: () => false, isRequired: false }),
    [`magicAuthToken`]: text({ access: () => false, isRequired: false }),
    [`magicAuthIssuedAt`]: timestamp({ access: () => false, isRequired: false }),
    [`magicAuthRedeemedAt`]: timestamp({ access: () => false, isRequired: false }),
  };

  /**
   * adminPageMiddleware
   *
   * Should be added to the admin.pageMiddleware stack.
   *
   * Redirects:
   *  - from the signin or init pages to the index when a valid session is present
   *  - to the init page when initFirstItem is configured, and there are no user in the database
   *  - to the signin page when no valid session is present
   */
  const adminPageMiddleware: Auth['admin']['pageMiddleware'] = async ({
    req,
    isValidSession,
    keystone,
  }) => {
    const pathname = url.parse(req.url!).pathname!;

    if (isValidSession) {
      if (pathname === '/signin' || (config.initFirstItem && pathname === '/init')) {
        return {
          kind: 'redirect',
          to: '/',
        };
      }
      return;
    }
    if (config.initFirstItem) {
      const { count } = await keystone.keystone.lists[config.listKey].adapter.itemsQuery(
        {},
        {
          meta: true,
        }
      );
      if (count === 0) {
        if (pathname !== '/init') {
          return {
            kind: 'redirect',
            to: '/init',
          };
        }
        return;
      }
    }

    if (pathname !== '/signin') {
      return {
        kind: 'redirect',
        to: '/signin',
      };
    }
  };

  /**
   * additionalFiles
   *
   * This function adds files to be generated into the Admin UI build. Must be added to the
   * admin.additionalFiles config.
   *
   * The signin page is always included, and the init page is included when initFirstItem is set
   */
  const additionalFiles: Auth['admin']['getAdditionalFiles'] = keystone => {
    let filesToWrite: AdminFileToWrite[] = [
      {
        mode: 'write',
        outputPath: 'pages/signin.js',
        src: signinTemplate({ gqlNames }),
      },
    ];
    if (config.initFirstItem) {
      const fields: Record<string, SerializedFieldMeta> = {};
      for (const fieldPath of config.initFirstItem.fields) {
        fields[fieldPath] = keystone.adminMeta.lists[config.listKey].fields[fieldPath];
      }

      filesToWrite.push({
        mode: 'write',
        outputPath: 'pages/init.js',
        src: initTemplate({ config, fields }),
      });
    }
    return filesToWrite;
  };

  /**
   * adminPublicPages
   *
   * Must be added to the admin.publicPages config
   */
  const adminPublicPages = ['/signin', '/init'];

  /**
   * extendGraphqlSchema
   *
   * Must be added to the extendGraphqlSchema config. Can be composed.
   */
  let extendGraphqlSchema = getExtendGraphQLSchema({
    ...config,
    protectIdentities: config.protectIdentities || false,
    gqlNames,
  });
  if (config.initFirstItem) {
    let existingExtendGraphqlSchema = extendGraphqlSchema;
    let extension = initFirstItemSchemaExtension({
      listKey: config.listKey,
      fields: config.initFirstItem.fields,
      extraCreateInput: config.initFirstItem.extraCreateInput,
      gqlNames,
    });
    extendGraphqlSchema = (schema, keystone) =>
      extension(existingExtendGraphqlSchema(schema, keystone), keystone);
  }

  /**
   * validateConfig
   *
   * Validates the provided auth config; optional step when integrating auth
   */
  const validateConfig = (keystoneConfig: KeystoneConfig) => {
    // List/listKey
    const specifiedListConfig = keystoneConfig.lists[config.listKey];
    if (keystoneConfig.lists[config.listKey] === undefined) {
      throw new Error(
        `In createAuth, you've specified the list ${JSON.stringify(
          config.listKey
        )} but you do not have a list named ${JSON.stringify(config.listKey)}`
      );
    }
    if (specifiedListConfig.fields[config.identityField] === undefined) {
      throw new Error(
        `In createAuth, you\'ve specified ${JSON.stringify(
          config.identityField
        )} as your identityField on ${JSON.stringify(config.listKey)} but ${JSON.stringify(
          config.listKey
        )} does not have a field named ${JSON.stringify(config.identityField)}`
      );
    }

    // Identity field
    // TODO: Check for String-like typing?
    const identityField = specifiedListConfig.fields[config.secretField];
    if (identityField === undefined) {
      throw new Error(
        `In createAuth, you've specified ${JSON.stringify(
          config.secretField
        )} as your secretField on ${JSON.stringify(config.listKey)} but ${JSON.stringify(
          config.listKey
        )} does not have a field named ${JSON.stringify(config.secretField)}`
      );
    }

    // Secret field
    // TODO: We could make the secret field optional to disable the standard id/secret auth and password resets (ie. magic links only)
    // const secretFieldInstance = specifiedListConfig.fields[config.secretField];
    // if (specifiedListConfig.fields[config.secretField] === undefined) {
    //   throw new Error(
    //     `In createAuth, you've specified ${JSON.stringify(
    //       config.secretField
    //     )} as your secretField on ${JSON.stringify(config.listKey)} but ${JSON.stringify(
    //       config.listKey
    //     )} does not have a field named ${JSON.stringify(config.secretField)}`
    //   );
    // }
    // if (
    //   typeof secretFieldInstance.compare !== 'function' ||
    //   secretFieldInstance.compare.length < 2
    // ) {
    //   throw new Error(
    //     `Field type specified does not support required functionality. ` +
    //       `createAuth for list '${listKey}' is using a secretField of '${secretField}'` +
    //       ` but field type does not provide the required compare() functionality.`
    //   );
    // }
    // if (typeof secretFieldInstance.generateHash !== 'function') {
    //   throw new Error(
    //     `Field type specified does not support required functionality. ` +
    //       `createAuth for list '${listKey}' is using a secretField of '${secretField}'` +
    //       ` but field type does not provide the required generateHash() functionality.`
    //   );
    // }

    for (const field of config.initFirstItem?.fields || []) {
      if (specifiedListConfig.fields[field] === undefined) {
        throw new Error(
          `In createAuth, you've specified the field ${JSON.stringify(
            field
          )} in initFirstItem.fields but it does not exist on the list ${JSON.stringify(
            config.listKey
          )}`
        );
      }
    }
  };

  /**
   * withAuth
   *
   * Automatically extends config with the correct auth functionality. This is the easiest way to
   * configure auth for keystone; you should probably use it unless you want to extend or replace
   * the way auth is set up with custom functionality.
   *
   * It validates the auth config against the provided keystone config, and preserves existing
   * config by composing existing extendGraphqlSchema functions and admin config.
   */
  const withAuth = (keystoneConfig: KeystoneConfig): KeystoneConfig => {
    validateConfig(keystoneConfig);
    let admin = keystoneConfig.admin;
    if (keystoneConfig.admin) {
      admin = {
        ...keystoneConfig.admin,
        publicPages: [...(keystoneConfig.admin.publicPages || []), ...adminPublicPages],
        getAdditionalFiles: [...(keystoneConfig.admin.getAdditionalFiles || []), additionalFiles],
        pageMiddleware: async args => {
          return (await adminPageMiddleware(args)) ?? keystoneConfig.admin?.pageMiddleware?.(args);
        },
        enableSessionItem: true,
      };
    }
    const existingExtendGraphQLSchema = keystoneConfig.extendGraphqlSchema;

    // Add the additional fields to the references lists fields object
    keystoneConfig.lists[config.listKey].fields = { ...keystoneConfig.lists[config.listKey].fields, ...additionalListFields };

    return {
      ...keystoneConfig,
      admin,
      extendGraphqlSchema: existingExtendGraphQLSchema
        ? (schema, keystone) =>
            existingExtendGraphQLSchema(extendGraphqlSchema(schema, keystone), keystone)
        : extendGraphqlSchema,
    };
  };

  /**
   * Alongside withAuth (recommended) all the config is returned so you can extend or replace
   * the default implementation with your own custom functionality, and integrate the result into
   * your keystone config by hand.
   */
  return {
    admin: {
      enableSessionItem: true,
      pageMiddleware: adminPageMiddleware,
      publicPages: adminPublicPages,
      getAdditionalFiles: additionalFiles,
    },
    fields: additionalListFields,
    extendGraphqlSchema,
    validateConfig,
    withAuth,
  };
}
