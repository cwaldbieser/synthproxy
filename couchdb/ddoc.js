{
   "membership": {
       "map": "function(doc) {
    var memberships = doc.memberOf;
    memberships.forEach(function(value){
        emit(doc._id, ["memberOf", value]);
        emit(value, ["member", doc._id]);
    })
    ;
}
