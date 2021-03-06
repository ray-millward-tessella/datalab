
function createDatabaseMock(items) {
  let lastInvocation;

  return () => ({
    find: (query) => {
      lastInvocation = { query };
      return { exec: () => Promise.resolve(items) };
    },
    findOne: (query) => {
      lastInvocation = { query };
      return { exec: () => Promise.resolve(items[0]) };
    },
    findOneAndUpdate: (query, entity, params) => {
      lastInvocation = { query, entity, params };
      return Promise.resolve(entity);
    },
    remove: (query) => {
      lastInvocation = { query };
      return { exec: () => Promise.resolve() };
    },
    exists: (query) => {
      lastInvocation = { query };
      return Promise.resolve(items.length > 0);
    },
    create: (entity) => {
      const wrappedEntity = {
        ...entity,
        toObject: () => entity,
      };
      lastInvocation = { entity };
      return Promise.resolve(wrappedEntity);
    },
    invocation: () => lastInvocation,
    query: () => lastInvocation.query,
    entity: () => lastInvocation.entity,
    params: () => lastInvocation.params,
    clear: () => { lastInvocation = undefined; },
  });
}

export default createDatabaseMock;
