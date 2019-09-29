const express = require('express');
const { graphql_client } = require('../graphql-client');

const {
  USER_MANAGEMENT_DATABASE_SCHEMA_NAME
} = require('../config');

const myBoom = require('../boom');
const verify_tool = require('../middlewares/verify');

let router = express.Router();

const schema_name = USER_MANAGEMENT_DATABASE_SCHEMA_NAME === 'public' ? '' :  USER_MANAGEMENT_DATABASE_SCHEMA_NAME.toString().toLowerCase() + '_';

router.get('/messages', verify_tool.jwt_verify, async (req, res, next) => {
  const { user } = req;
  const limit = req.query.limit || 0;
  const offset = req.query.offset || 0;
  let query = `
  query myInbox($user_id: Int!) {
    unread_message_num: user_messages_aggregate(where: {_and: {readed: {_eq: false}, trashed: {_eq: false}}, user_id: {_eq: $user_id}}) {
      get: aggregate {
        value: count(columns: id)
      }
    }
    unread_messages: ${schema_name}user_messages(offset: ${offset}, limit: ${limit}, where: {_and: {readed: {_eq: false}, trashed: {_eq: false}}, user_id: {_eq: $user_id}}) {
      id
      title
      readed
      trashed
    }
    readed_message_num: user_messages_aggregate(where: {_and: {readed: {_eq: false}, trashed: {_eq: false}}, user_id: {_eq: $user_id}}) {
      get: aggregate {
        value: count(columns: id)
      }
    }
    readed_messages: ${schema_name}user_messages(offset: ${offset}, limit: ${limit}, where: {_and: {readed: {_eq: false}, trashed: {_eq: false}}, user_id: {_eq: $user_id}}) {
      id
      title
      readed
      trashed
    }
    trashed_message_num: user_messages_aggregate(where: {_and: {readed: {_eq: false}, trashed: {_eq: false}}, user_id: {_eq: $user_id}}) {
      get: aggregate {
        value: count(columns: id)
      }
    }
    trashed_messages: ${schema_name}user_messages(offset: ${offset}, limit: ${limit}, where: {trashed: {_eq: true}, user_id: {_eq: $user_id}}) {
      id
      title
      readed
      trashed
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      user_id: user.id,
    });
  } catch (e) {
    console.error(e);
    return next(myBoom.wrapError(500, 50000, `graphql <${e.message}>`));
  }

  // return user as json response
  res.json(hasura_data);
});

router.put('/messages/:id', verify_tool.jwt_verify, async (req, res, next) => {
  const messageId = req.param.id;
  let query = `
  mutation ($id: Int!){
    update_${schema_name}user_messages(
      where: {id: {_eq: $id}}
      _set: {
        readed: true
      }
    )
    {
      affected_rows
    }
  }
  `;

  let hasura_data;
  try {
    hasura_data = await graphql_client.request(query, {
      id: messageId,
    });
  } catch (e) {
    console.error(e);
    return next(myBoom.wrapError(500, 50000, `graphql <${e.message}>`));
  }

  if (hasura_data[`update_${schema_name}user_messages`].affected_rows === 0) {
    console.warn('The message is not found');
  }

  res.send('OK');
});

module.exports = router;
