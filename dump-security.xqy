(:
  Dumps the security amps, roles, and users 
  Author: Hunter Williams
:)

xquery version "1.0-ml";
import module namespace sec="http://marklogic.com/xdmp/security" at 
    "/MarkLogic/security.xqy";

declare variable $ml-default-roles := ("pipeline-execution","sql-execution","view-admin","pipeline-management","manage-admin",
  "admin-builtins","welcome-internal","trigger-management","app-builder-internal","xinclude","rest-reader","hadoop-user-read",
  "alert-internal","pki","app-builder","qconsole-user","qconsole-internal","xa","infostudio-admin-internal","rest-internal",
  "ec2-protected-access","xa-admin","admin-module-internal","plugin-internal","flexrep-user","flexrep-admin","network-access",
  "domain-management","tiered-storage-admin","alert-admin","rest-writer-internal","custom-dictionary-admin","flexrep-eval",
  "dls-admin","manage-internal","filesystem-access","merge","alert-user","rest-admin","infostudio-user","dls-internal",
  "security","infostudio-internal","rest-reader-internal","custom-dictionary-user","application-plugin-registrar",
  "search-internal","flexrep-user-change","tiered-storage-internal","alert-execution","manage-user","appservices-internal",
  "view-admin-internal","rest-extension-user","hadoop-internal","app-user","hadoop-user-all","rest-writer","manage-admin-internal",
  "rest-admin-internal","flexrep-internal","healthcheck-user","cpf-restart","admin","dls-user","hadoop-user-write");

declare variable $ml-default-users := ("infostudio-admin","admin","nobody","healthcheck");
declare function local:print-collection($collection as xs:string){
    <collection>{$collection}</collection>
};
declare function local:print-role-name($role-id as xs:unsignedLong){
   <role-name>{fn:doc(fn:concat(sec:roles-collection(),"/",$role-id))/sec:role/sec:role-name/text()}</role-name>
};
declare function local:print-permission($default-permission as element(sec:permission)){
    let $capability := $default-permission/sec:capability/text()
    let $role-id := $default-permission/sec:role-id
    return 
    <permission>
        <capability>{$capability}</capability>
        {local:print-role-name($role-id)}
    </permission>
};
declare function local:print-role($role as element(sec:role)){
let $role-name := $role/sec:role-name/text()
return
  <role>
  <name>{$role-name}</name>
  <description>{$role/sec:description/text()}</description>
  {local:print-collection($role/sec:collections//sec:uri)}
  {local:print-permission($role/sec:permissions/sec:permission)}
  {local:print-role-name($role/sec:role-ids/sec:role-id)}
  </role>
};
declare function local:print-amp-role($role-id as xs:unsignedLong){
   <role>{local:get}</role>
};
declare function local:get-database($db as xs:unsignedLong){
   if ($db = 0) then
     0
   else
     xdmp:database-name($db)
};
declare function local:print-amp($amp as element(sec:amp)){
  <amp>
    <namespace>{$amp/sec:namespace/text()}</namespace>
    <local-name>{$amp/sec:local-name/text()}</local-name>
    <document-uri>{$amp/sec:document-uri/text()}</document-uri>
    <database>{local:get-database($amp/sec:database/text())}</database>
    {local:print-role-name($amp/sec:role-ids/sec:role-id)}
  </amp>
};

declare function local:print-user($user as element(sec:user)){
   <user>
   <name>{$user/sec:user-name/text()}</name>
   <description>{$user/sec:description/text()}</description>
   {local:print-collection($user/sec:collections/sec:uri)}
   {local:print-permission($user/sec:permission)}
   {local:print-role-name($user/sec:role-ids/sec:role-id)}
   </user>
};

declare function local:get-roles(){
  cts:search(fn:doc(),cts:directory-query(fn:concat(sec:roles-collection(),"/"),"1"))
};

declare function local:get-amps(){
  cts:search(fn:doc(),cts:directory-query(fn:concat(sec:amps-collection(),"/"),"1"))
};

declare function local:get-users(){
  cts:search(fn:doc(),cts:directory-query(fn:concat(sec:users-collection(),"/"),"1"))
};

declare function local:print-all-users(){
  let $users := local:get-users()
  return <users>{local:print-user($users/sec:user)}</users>
};

declare function local:print-all-amps(){
  let $amps := local:get-amps()
  return <amps>{local:print-amp($amps/sec:amp)}</amps>
};

declare function local:print-all-roles(){
  let $roles := local:get-roles()
  return <roles>{local:print-role($roles/sec:role)}</roles>
};

declare function local:dump-security(){
  <security>{(local:print-all-users(),local:print-all-amps(),local:print-all-roles())}</security>
};

declare function local:create-role-if-dne($role-name){
  if (sec:role-exists($role-name)) then
    ()
  else
    let $_ := sec:create-role($role-name, (), (), (), ())
    return fn:concat("created role:",$role-name)
};

declare function local:load-role($role){
  if (fn:not(sec:role-exists($role/name))) then
    fn:concat("role dne:",$role/name)
  else
    let $_ := sec:role-set-description($role/name, $role/description)
    let $_ := sec:role-set-roles($role/name, $role/role-name)
    let $_ := sec:role-set-default-collections($role/name, $role/collection)
    let $_ := sec:role-set-default-permissions($role/name, local:permissions-to-permissions($role))
    return ()
};

declare function local:permissions-to-permissions($holder){
  for $p in $holder/permission
    return xdmp:permission($p/role-name,$p/capability)
};

declare function local:create-user($user,$skip-if-dne,$only-add-user-roles){
  if (fn:not(sec:user-exists($user/name))) then 
      if ($skip-if-dne) then
        fn:concat("user dne - not making:",$user/name)
      else
        let $_ := sec:create-user($user/name, $user/description, fn:concat($user/name,"123"), $user/role-name,
          local:permissions-to-permissions($user), $user/collection)
        return fn:concat("user created:",$user/name)
  else
    let $_ := sec:user-set-description($user/name, $user/description)
    let $_ := 
      if ($only-add-user-roles) then
        sec:user-set-roles($user/name, $user/role-name)
      else
        sec:user-add-roles($user/name, $user/role-name)
    let $_ := sec:user-set-default-collections($user/name, $user/collection)
    let $_ := sec:user-set-default-permissions($user/name, local:permissions-to-permissions($user))
    return ()
};

declare function local:load-security($security,$skip-creating-users,$only-add-user-roles){
  let $roles-created := local:load-security-create-roles($security)
  let $roles-modified := 
    for $r in $security//role
      return local:load-role($r)

  let $users-created := 
    for $u in $security//user
      return local:create-user($u,$skip-creating-users,$only-add-user-roles)

  return ($roles-created,$roles-modified,$users-created)
};

declare function local:load-security-create-roles($security){
    for $r in $security//role
      return local:create-role-if-dne($r/name)
};

declare function local:diff-roles($security-superset,$security-subset){
  let $superset-map := map:map()
  let $subset-map := map:map()

  let $_ := 
    for $r in $security-superset//role
    return map:put($superset-map,$r/name,$r/role-name)
  let $_ := 
    for $r in $security-subset//role
      return map:put($subset-map,$r/name,$r/role-name)

  return <roles-diff comment="subset lacks these">{local:diff-map-to-xml("role",$superset-map - $subset-map)}</roles-diff>
};

declare function local:diff-users($security-superset,$security-subset){
  let $superset-map := map:map()
  let $subset-map := map:map()

  let $_ := 
    for $u in $security-superset//user
    return map:put($superset-map,$u/name,$u/role-name)
  let $_ := 
    for $u in $security-subset//user
      return map:put($subset-map,$u/name,$u/role-name)

  return <users-diff comment="subset lacks these">{local:diff-map-to-xml("user",$superset-map - $subset-map)}</users-diff>
};

declare function local:diff-map-to-xml($element-type,$map as map:map){
    for $key in map:keys($map)
      let $values := map:get($map,$key)
      let $name := element {"name"} {$key}   
      return element {$element-type} {($name,$values)}
};

declare function local:diff-security($security-superset,$security-subset){
  (local:diff-users($security-superset, $security-subset),local:diff-roles($security-superset, $security-subset))
};

local:dump-security()