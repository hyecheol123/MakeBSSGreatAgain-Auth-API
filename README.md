# MakeBSSGreatAgain Auth API

[![Code Style: Google](https://img.shields.io/badge/code%20style-google-blueviolet.svg)](https://github.com/google/gts)

Authentication API for Make BSS Great Again Project
Using [Generic Auth API](https://github.com/hyecheol123/generic-auth-api) as template.

Supported API and features are listed in the [API Documentation](https://hyecheol123.github.io/MakeBSSGreatAgain-API-Documentation/#section/SecuritySchemes)


## Scripts

Here is the list for supported npm/yarn scripts.
These are used to lint, test, build, and run the code.

1. `lint`: lint the code
2. `lint:fix`: lint the code and try auto-fix
3. `build`: compile typescript codes (destination: `dist` directory)
4. `clean`: remove the compiled code
5. `start`: run the codes
6. `test`: run the test codes


## Dependencies/Environment

Developed and tested with `Ubuntu 20.04.2 LTS`, with `Node v14.16.0`.

To configure the typescript development environment easily, [gts](https://github.com/google/gts) has been used.
Based on the `gts` style rules, I modified some to enforce rules more strictly.
To see the modification, please check [`.eslintrc.json` file](https://github.com/hyecheol123/generic-auth-api/blob/main/.eslintrc.json).

For the database, this project is relying on [MariaDB](https://mariadb.org/), which almost identical with the MySQL.
In this project, all informations are stored in `auth_api` database.  

SQL Query to create `user` table is 
``` SQL
CREATE TABLE user (
  username VARCHAR(12) NOT NULL PRIMARY KEY,
  password CHAR(88) NOT NULL,
  membersince TIMESTAMP NULL DEFAULT NULL,
  admin BOOLEAN NOT NULL);
```

SQL Query to create `session` table is
``` SQL
CREATE TABLE session (
  token VARCHAR(400) NOT NULL PRIMARY KEY,
  expiresAt TIMESTAMP NULL DEFAULT NULL,
  username VARCHAR(12) NOT NULL,
  INDEX usernameIdx(username));
```

[Express](https://expressjs.com/) is a web framework for node.js.
This project used it to develop and maintain APIs more conveniently.

[ajv](https://ajv.js.org/) is used for runtime type checks.