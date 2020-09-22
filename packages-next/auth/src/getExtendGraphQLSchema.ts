import { graphQLSchemaExtension } from '@keystone-spike/keystone/schema';
import { ResolvedAuthGqlNames, SendTokenFn } from './types';
import { randomBytes } from 'crypto';

// TODO: Should put a utility function like this somewhere else?
let generateToken = function (length: number): string {
  return randomBytes(length)
    .toString('base64')
    .slice(0, length)
    .replace(/[^a-zA-Z0-9]/g, '');
};

// TODO: Not produciton ready; logging auth tokens to the console ain't very secure
const buildDefaultSendFn = (linkType: string) =>
  function (args: { itemId: string | number; identity: string; token: string }): void {
    console.log(`Sending ${linkType} link:`, args);
  };

export function getExtendGraphQLSchema({
  listKey,
  identityField,
  secretField,
  protectIdentities,
  gqlNames,
  passwordResetLink: { sendToken: sendPasswordResetLink } = {
    sendToken: buildDefaultSendFn('Password Reset'),
  },
  magicAuthLink: { sendToken: sendMagicAuthLink } = { sendToken: buildDefaultSendFn('Magic Auth') },
}: {
  listKey: string;
  identityField: string;
  secretField: string;
  protectIdentities: boolean;
  gqlNames: ResolvedAuthGqlNames;
  passwordResetLink?: { sendToken: SendTokenFn };
  magicAuthLink?: { sendToken: SendTokenFn };
}) {
  // Validate the list config part of AuthConfig against the list schema
  // TODO: This only needs to run once (but after list have init'ed, etc.); memoize?
  // TODO: Is it possible to refactor this to leverage ts type checking? Using type guards maybe..?
  function validateConfig(args: Record<string, string>, list: any): void {
    const secretFieldInstance = list.fieldsByPath[secretField];
    if (
      typeof secretFieldInstance.compare !== 'function' ||
      secretFieldInstance.compare.length < 2
    ) {
      throw new Error(
        `Field type specified does not support required functionality. ` +
          `createAuth for list '${listKey}' is using a secretField of '${secretField}'` +
          ` but field type does not provide the required compare() functionality.`
      );
    }
    if (typeof secretFieldInstance.generateHash !== 'function') {
      throw new Error(
        `Field type specified does not support required functionality. ` +
          `createAuth for list '${listKey}' is using a secretField of '${secretField}'` +
          ` but field type does not provide the required generateHash() functionality.`
      );
    }
    // TODO: Also validate the identity field is Stringy?
  }

  async function attemptAuthentication(
    args: Record<string, string>,
    list: any
  ): Promise<
    | {
        success: false;
        message: string;
      }
    | {
        success: true;
        message: string;
        // Do we not have an `item` type defined already..?
        item: { id: any; [prop: string]: any };
  }
  > {
    const genericFailure = '[passwordAuth:failure] Authentication failed';
    const identity = args[identityField];
    const canidatePlaintext = args[secretField];
    const secretFieldInstance = list.fieldsByPath[secretField];

    // TODO: Allow additional filters to be suppled in config? eg. `validUserConditions: { isEnable: true, isVerified: true, ... }`
    const items = await list.adapter.find({ [identityField]: identity });

    // Identity failures with helpful errors
    let specificFailure: string | undefined;
    if (items.length === 0) {
      specificFailure = `[passwordAuth:identity:notFound] The ${identityField} value provided didn't identify any ${list.adminUILabels.plural}`;
    } else if (items.length === 1 && !items[0][secretField]) {
      specificFailure = `[passwordAuth:secret:notSet] The ${list.adminUILabels.singular} identified has no ${secretField} set so can not be authenticated`;
    } else if (items.length > 1) {
      specificFailure = `[passwordAuth:identity:multipleFound] The ${identityField} value provided identified more than one ${list.adminUILabels.singular}`;
    }
    if (typeof specificFailure !== 'undefined') {
      // If we're trying to maintain the privacy of accounts (hopefully, yes) make some effort to prevent timing attacks
      // Note, we're not attempting to protect the hashing comparisson itself from timing attacks, just _the existance of an item_
      // We can't assume the work factor so can't include a pre-generated hash to compare but generating a new hash will create a similar delay
      // Changes to the work factor, latency loading the item(s) and many other factors will still be detectable by a dedicated attacker
      // This is far from perfect (but better than nothing)
      protectIdentities &&
        (await secretFieldInstance.generateHash('simulated-password-to-counter-timing-attack'));
      return { success: false, message: protectIdentities ? genericFailure : specificFailure };
    }

    const item = items[0];
    const isMatch = await secretFieldInstance.compare(canidatePlaintext, item[secretField]);
    if (!isMatch) {
      specificFailure = `[passwordAuth:secret:mismatch] The ${secretField} provided is incorrect`;
      return { success: false, message: protectIdentities ? genericFailure : specificFailure };
    }

    // Authenticated!
    return { success: true, item, message: 'Authentication successful' };
    }

  async function updateAuthToken(
    tokenType: string,
    identity: string,
    list: any,
    ctx: any
  ): Promise<
    | {
        success: true;
        message: string;
        itemId: string | number;
        token: string;
    }
    | {
        success: false;
        message: string;
  }
  > {
    const genericFailure = `[${tokenType}:failure] Token generation failed`;
    const items = await list.adapter.find({ [identityField]: identity });

    // Identity failures with helpful errors
    let specificFailure: string | undefined;
    if (items.length === 0) {
      specificFailure = `[${tokenType}:identity:notFound] The ${identityField} value provided didn't identify any ${list.adminUILabels.plural}`;
    } else if (items.length > 1) {
      specificFailure = `[${tokenType}:identity:multipleFound] The ${identityField} value provided identified more than one ${list.adminUILabels.singular}`;
    }
    if (typeof specificFailure !== 'undefined') {
      return { success: false, message: protectIdentities ? genericFailure : specificFailure };
    }

    const item = items[0];
    const token = generateToken(20);

    // Save the token and related info back to the item
    // TODO: Should we also unset the password field here if tokenType is 'passwordReset'?
    const { errors } = await ctx.keystone.executeGraphQL({
      context: ctx.keystone.createContext({ skipAccessControl: true }),
      query: `mutation($id: String, $token: String, $now: String) {
        updateUser(id: $id, data: {
          ${tokenType}Token: $token,
          ${tokenType}IssuedAt: $now,
          ${tokenType}RedeemedAt: null
        }) { id }
      }`,
      variables: { id: item.id, token, now: new Date().toISOString() },
    });
    if (Array.isArray(errors) && errors.length > 0) {
      console.error(errors[0] && (errors[0].stack || errors[0].message));
    return {
      success: false,
        message: `[${tokenType}:error] Internal error encountered`,
    };
  }

    return { success: true, message: 'Token generated!', itemId: item.id, token };
  }

  // Note that authenticate${listKey}WithPassword is non-nullable because it throws when auth fails
  // .. though it shouldn't, https://github.com/keystonejs/keystone/issues/2300
  return graphQLSchemaExtension({
    typeDefs: `
      union AuthenticatedItem = ${listKey}
      type Query {
        authenticatedItem: AuthenticatedItem
      }
      type Mutation {
        ${gqlNames.authenticateItemWithPassword}(${identityField}: String!, ${secretField}: String!): ${gqlNames.ItemAuthenticationWithPasswordResult}!
      }
      type ${gqlNames.ItemAuthenticationWithPasswordResult} {
          token: String!
          item: ${listKey}!
      }
      type Mutation {
        ${gqlNames.sendItemPasswordResetLink}(${identityField}: String!): ${gqlNames.sendItemPasswordResetLinkResult}!
      }
      type ${gqlNames.sendItemPasswordResetLinkResult} {
        success: Boolean!
        message: String!
      }
      type Mutation {
        ${gqlNames.sendItemMagicAuthLink}(${identityField}: String!): ${gqlNames.sendItemMagicAuthLinkResult}!
      }
      type ${gqlNames.sendItemMagicAuthLinkResult} {
        success: Boolean!
        message: String!
      }
    `,
    resolvers: {
      Mutation: {
        async [gqlNames.authenticateItemWithPassword](root: any, args: any, ctx: any) {
          validateConfig(args, ctx.keystone.lists[listKey]);
          const result = await attemptAuthentication(args, ctx.keystone.lists[listKey]);
          if (!result.success) {
            // TODO: Don't error on failure, https://github.com/keystonejs/keystone/issues/2300
            throw new Error(result.message);
          }
          const token = await ctx.startSession({ listKey: 'User', itemId: result.item.id });
          return {
            token,
            item: result.item,
          };
        },
        async [gqlNames.sendItemPasswordResetLink](root: any, args: any, ctx: any) {
          const list = ctx.keystone.lists[listKey];
          const identity = args[identityField];
          validateConfig(args, list);
          const result = await updateAuthToken('passwordReset', identity, list, ctx);
          if (result.success) {
            await sendPasswordResetLink({ itemId: result.itemId, identity, token: result.token });
          }
          return {
            success: result.success,
            message: result.message,
          };
        },
        async [gqlNames.sendItemMagicAuthLink](root: any, args: any, ctx: any) {
          const list = ctx.keystone.lists[listKey];
          const identity = args[identityField];
          validateConfig(args, list);
          const result = await updateAuthToken('magicAuth', identity, list, ctx);
          if (result.success) {
            await sendMagicAuthLink({ itemId: result.itemId, identity, token: result.token });
          }
          return {
            success: result.success,
            message: result.message,
          };
        },
      },
      Query: {
        async authenticatedItem(root: any, args: any, ctx: any) {
          if (typeof ctx.session?.itemId === 'string' && typeof ctx.session.listKey === 'string') {
            const item = (
              await ctx.keystone.lists[ctx.session.listKey].adapter.find({
                id: ctx.session.itemId,
              })
            )[0];
            if (!item) return null;
            return {
              ...item,
              // TODO: is this okay?
              // probably yes but ¯\_(ツ)_/¯
              __typename: ctx.session.listKey,
            };
          }
          return null;
        },
      },
      AuthenticatedItem: {
        __resolveType(rootVal: any) {
          return rootVal.__typename;
        },
      },
    },
  });
}
