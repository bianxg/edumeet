var records = [
    { id: 1, username: 'jack', password: 'secret', displayName: 'Jack', emails: [ { value: 'jack@example.com' } ] }
  , { id: 2, username: 'jill', password: 'birthday', displayName: 'Jill', emails: [ { value: 'jill@example.com' } ] }
  , { id: 3, username: 'bxg', password: 'mmmmmm', displayName: 'bxg', emails: [ { value: 'jill@example.com' } ] }
  , { id: 4, username: 'test1', password: 'mmmmmm', displayName: 'test1', emails: [ { value: 'jill@example.com' } ] }
  , { id: 5, username: 'test2', password: 'mmmmmm', displayName: 'test2', emails: [ { value: 'jill@example.com' } ] }
  , { id: 6, username: 'test3', password: 'mmmmmm', displayName: 'test3', emails: [ { value: 'jill@example.com' } ] }
  , { id: 7, username: 'test4', password: 'mmmmmm', displayName: 'test4', emails: [ { value: 'jill@example.com' } ] }
  , { id: 8, username: 'test5', password: 'mmmmmm', displayName: 'test5', emails: [ { value: 'jill@example.com' } ] }
  , { id: 9, username: 'test6', password: 'mmmmmm', displayName: 'test6', emails: [ { value: 'jill@example.com' } ] }
  , { id: 10, username: 'test7', password: 'mmmmmm', displayName: 'test7', emails: [ { value: 'jill@example.com' } ] }
  , { id: 11, username: 'test8', password: 'mmmmmm', displayName: 'test8', emails: [ { value: 'jill@example.com' } ] }
];

exports.findById = function(id, cb) {
  process.nextTick(function() {
    var idx = id - 1;
    if (records[idx]) {
      cb(null, records[idx]);
    } else {
      cb(new Error('User ' + id + ' does not exist'));
    }
  });
}

exports.findByUsername = function(username, cb) {
  process.nextTick(function() {
    for (var i = 0, len = records.length; i < len; i++) {
      var record = records[i];
      if (record.username === username) {
        return cb(null, record);
      }
    }
    return cb(null, null);
  });
}

exports.getById = function(id) {  
  return new Promise(function(resolve,reject) {
    process.nextTick(function() {
      var idx = id - 1;
      if (records[idx]) {
        resolve(records[idx]);
      }
      else {
        reject(new Error('User ' + id + ' does not exist'));
      }
    });
  });
} 
