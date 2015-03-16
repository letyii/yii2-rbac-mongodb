yii2-rbac-mongodb
=================

RBAC Mongodb for Yiiframework 2

## Installation
The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require "letyii/yii2-rbac-mongodb" "dev-master"
```
or add

```json
"letyii/yii2-rbac-mongodb": "dev-master"
```

to the require section of your application's `composer.json` file.

## Usage Example
~~~php
'components' => [
    // the rest of your components section
    'authManager' => [
        'class' => 'letyii\rbacmongodb\MongodbManager',
    ],
]
~~~

github: https://github.com/letyii/yii2-rbac-mongodb

packagist: https://packagist.org/packages/letyii/yii2-rbac-mongodb
