### Introduction

NGX_HTTP_HANDLERSOCKET_JSON_MODULE is an [nginx] (http://nginx.org/) module to get full use of [HandlerSocket] (https://github.com/ahiguti/HandlerSocket-Plugin-for-MySQL) for [MySQL] (http://www.mysql.com). 

### Installation

1. Configure nginx with option --add-module=/full/path/to/dir/nginx_http_handlersocket_json_module
2. make
3. sudo make install

### Configuration

Configuration options should be used in a location context of nginx config file.

#### Example 1

	location ~ /cities/(.+)/$ {
		hs_json;				# enable module

		hs_json_host 127.0.0.1;	# IP address of MySQL server (127.0.0.1 by default)
		hs_json_port 9998;		# port at which HandlerSocket is listening (9998 by default)

		hs_json_db test;		# database name
		hs_json_table city;		# table name

		hs_json_index name;		# index name (PRIMARY key is used by default)
		hs_json_fields name,id;	# fields to include in output

		hs_json_op "=";			# operator ("=" by default)
								# possible values: =, <, <=, >, >=
		hs_json_limit 10;		# maximum number of records to be returned (10 by default)

		set $hs_request $1;		# the set source input data 
	}

This example will produce the following output:

	curl http://localhost/cities/san/
	[{"name":"San Amaro", "id": "12"},{"name":"San Andreas", "id": "13"},{"name":"San Andrs", "id": "14"} ... ]

#### Example 2

Setting GET variable as a search parameter:

	location ~ /json {
		set $hs_request $get_id;
	}

### Errors

* 500 — incorrect configuration or some sort of protocol misbehaviour/misconfiguration or HadlerSocket error
* 503 — IO error or connection error while trying to connect to HandlerSocket

In case of empty set error 404 will NOT be returned. Instead an empty JSON response ({[]}) will be generated.
	
### Limitations

* Output data size is limited to 1Kb. You can increase this limit by changing BUFF_SIZE constant (`#define BUFF_SIZE`).
* Only one field can be used as search criteria.

### More info

[Original description at Habrahabr] (http://habrahabr.ru/blogs/nginx/115920/) (in Russian).