(:Allows user to backup multiple databases on demand
  Hunter Williams - https://github.com/hunterwilliams/marklogic-misc
  :)
declare namespace e = "http://marklogic.com/xdmp/error";
declare variable $BUILT-IN-DBS := ("Security","Meters","App-Services","Extensions","Fab","Modules","Schemas","Last-Login","Triggers","Documents");

declare variable $DBS-TO-SELECT as xs:string* := xdmp:database-name(xdmp:databases());
declare variable $DBS-TO-IGNORE := ("IgnoreThisDBToo",$BUILT-IN-DBS);
declare variable $BACKUP-DIR as xs:string := "/data/MarkLogic/ManualBackups/";
declare variable $DEBUG as xs:boolean := fn:true();

declare function local:backup($db as xs:string){
  try { 
        let $backup-directory := fn:concat($BACKUP-DIR,$db)
        let $backup-id := xdmp:database-backup(xdmp:database-forests(xdmp:database($db)),$backup-directory)
        return fn:concat($db,":",$backup-id)
      }
  catch($e) { fn:concat($db," failed to backup - (",$e//e:code,":",$e//e:message,")") }
};

let $skip-dbs := for $fix-case in $DBS-TO-IGNORE return fn:lower-case($fix-case)

return for $database in $DBS-TO-SELECT
       where fn:not(fn:lower-case($database) = $skip-dbs)
       order by $database
       return 
          if ($DEBUG) then
            $database
          else
            local:backup($database)