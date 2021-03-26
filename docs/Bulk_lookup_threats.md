# Returns weather or not threats are in the database

### Using input files
This command can read one or multiple files at the same time as atom input. To pass them, using `-i` or `--input` 
argument followed by the relative or absolute path.

**file format**: `<ATOM_TYPE>:<FILE_PATH>`  
  Here, the command will expect that each line represents a single atom of given type. For example, the following file 
  contains only domains and it should be passe as `domain:path/to/file.txt`.
  ```
  threat1.com
  anotherthreat.fr
  en.wikipedia
  ```

  ```shell
  $ ocd-dt bulk_lookup_threats -i ip:path/to/file/myiplist.txt -i file:path/to/file/myfilelist.txt
                                  --------- ip typed ---------    --------- file typed -----------
  ```

### Passing atoms by CLI
As input files, you can pass one or multiple atoms by CLI. Each atom has its own flag called exactly the same as th atom type.
  ```shell
  $ ocd-dt bulk_lookup_threats --ip 113.223.40.103 --ip 5.78.23.158 --domain reverso.net  --file f0f5d30e91006c8ca7a528f26432ftt5 
  ```     

With all that in mind, you can combine them to fit your needs:
```shell
$ ocd-dt bulk_lookup_threats  --domain paiza.com --ip 45.96.65.132 -i ip:path/to/file/myiplist.txt
                              ---typed domain--- ----typed ip----  -------typed file as ip--------                                                
```

    
### Parameters

* Optional arguments
    > -h, --help   
    show this help message and exit

    > -o [OUTPUT], --output [OUTPUT]  
    file path from script
  
    > -e {prod,preprod}, --env {prod,preprod}     
    execute on specified environment (Default: prod)

    > --debug
  
    > -q, --quiet  
    Silence the output to only show warnings/errors
  
    > -ad, --atom-details  
    returns threats full details
   
    > -i INPUT, --input INPUT  
    read threats to add from FILE.
  
* Typed atom flags
    > --apk APK             
    --asn ASN             
    -cc CC               
    --crypto CRYPTO       
    --cve CVE             
    --domain DOMAIN       
    --email EMAIL         
    --file FILE           
    --fqdn FQDN           
    --iban IBAN           
    --ip IP               
    --ip_range IP_RANGE   
    --paste PASTE         
    --phone_number PHONE_NUMBER  
    --regkey REGKEY
    --ssl SSL
    --url URL