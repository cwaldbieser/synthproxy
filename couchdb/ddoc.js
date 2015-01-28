{
   "attrib_view": {
       "map": "function(doc) {\n    var dn = doc.dn;\n    var attrib = doc.attrib;\n    var order = 0;\n    if(\"order\" in doc)\n    {\n        order = doc.order;\n    }\n    var value = doc.value;\n    if(attrib == \"memberOf\")\n    {\n        var group = value;\n\temit([dn, \"memberOf\", order], [\"memberOf\", group]);\n        emit([group, \"member\", dn], [\"member\", dn]);\n    }\n    else\n    {\n        emit([dn, attrib, order], [attrib, value]);\n    }\n}"
   }
}
