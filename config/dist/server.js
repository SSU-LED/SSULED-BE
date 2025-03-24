/*
 * ATTENTION: The "eval" devtool has been used (maybe by default in mode: "development").
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./config/logging.config.ts":
/*!**********************************!*\
  !*** ./config/logging.config.ts ***!
  \**********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
eval("\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.winstonConfig = void 0;\nconst nest_winston_1 = __webpack_require__(/*! nest-winston */ \"nest-winston\");\nconst winston = __webpack_require__(/*! winston */ \"winston\");\nexports.winstonConfig = {\n    transports: [\n        new winston.transports.Console({\n            level:  false ? 0 : 'debug',\n            format: winston.format.combine(winston.format.timestamp(), nest_winston_1.utilities.format.nestLike('SSULED', {\n                prettyPrint: true,\n                colors: true,\n            })),\n        }),\n        new winston.transports.File({\n            filename: 'logs/error.log',\n            level: 'error',\n            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),\n        }),\n        new winston.transports.File({\n            filename: 'logs/combined.log',\n            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),\n        }),\n    ],\n};\n\n\n//# sourceURL=webpack://ssu-led-backend/./config/logging.config.ts?");

/***/ }),

/***/ "./config/orm.config.ts":
/*!******************************!*\
  !*** ./config/orm.config.ts ***!
  \******************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
eval("\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AppDataSource = exports.dataSourceOptions = exports.typeOrmConfig = void 0;\nconst typeorm_1 = __webpack_require__(/*! typeorm */ \"typeorm\");\nconst dotenv_1 = __webpack_require__(/*! dotenv */ \"dotenv\");\nconst user_seeder_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error(\"Cannot find module 'database/seeds/user.seeder'\"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));\nconst auth_seeder_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error(\"Cannot find module 'database/seeds/auth.seeder'\"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));\nconst group_seeder_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error(\"Cannot find module 'database/seeds/group.seeder'\"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));\nconst post_seeder_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error(\"Cannot find module 'database/seeds/post.seeder'\"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));\nconst nodeEnv = \"development\" || 0;\n(0, dotenv_1.config)({ path: `env/.${nodeEnv}.env` });\nconst typeOrmConfig = (configService) => {\n    return {\n        type: 'postgres',\n        host: configService.get('DB_HOST') || 'localhost',\n        port: parseInt(configService.get('DB_PORT') || '5432', 10),\n        username: configService.get('DB_USERNAME') || 'postgres',\n        password: configService.get('DB_PASSWORD') || 'postgres',\n        database: configService.get('DB_DATABASE') || 'ssuled',\n        entities: [__dirname + '/../**/*.entity.{js,ts}'],\n        synchronize: configService.get('NODE_ENV') !== 'production',\n        logging: configService.get('NODE_ENV') !== 'production',\n        migrations: [__dirname + '/../database/migrations/**/*.{js,ts}'],\n        migrationsTableName: 'migrations',\n    };\n};\nexports.typeOrmConfig = typeOrmConfig;\nexports.dataSourceOptions = {\n    type: 'postgres',\n    host: process.env.DB_HOST || 'localhost',\n    port: parseInt(process.env.DB_PORT || '5432', 10),\n    username: process.env.DB_USERNAME || 'postgres',\n    password: process.env.DB_PASSWORD || 'postgres',\n    database: process.env.DB_DATABASE || 'ssuled',\n    entities: [__dirname + '/../**/*.entity.{js,ts}'],\n    migrations: [__dirname + '/../database/migrations/**/*.{js,ts}'],\n    migrationsTableName: 'migrations',\n    seeds: [user_seeder_1.UserSeeder, auth_seeder_1.AuthSeeder, group_seeder_1.GroupSeeder, post_seeder_1.PostSeeder],\n};\nexports.AppDataSource = new typeorm_1.DataSource(exports.dataSourceOptions);\nexports[\"default\"] = exports.typeOrmConfig;\n\n\n//# sourceURL=webpack://ssu-led-backend/./config/orm.config.ts?");

/***/ }),

/***/ "./node_modules/webpack/hot/log-apply-result.js":
/*!******************************************************!*\
  !*** ./node_modules/webpack/hot/log-apply-result.js ***!
  \******************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

eval("/*\n\tMIT License http://www.opensource.org/licenses/mit-license.php\n\tAuthor Tobias Koppers @sokra\n*/\n\n/**\n * @param {(string | number)[]} updatedModules updated modules\n * @param {(string | number)[] | null} renewedModules renewed modules\n */\nmodule.exports = function (updatedModules, renewedModules) {\n\tvar unacceptedModules = updatedModules.filter(function (moduleId) {\n\t\treturn renewedModules && renewedModules.indexOf(moduleId) < 0;\n\t});\n\tvar log = __webpack_require__(/*! ./log */ \"./node_modules/webpack/hot/log.js\");\n\n\tif (unacceptedModules.length > 0) {\n\t\tlog(\n\t\t\t\"warning\",\n\t\t\t\"[HMR] The following modules couldn't be hot updated: (They would need a full reload!)\"\n\t\t);\n\t\tunacceptedModules.forEach(function (moduleId) {\n\t\t\tlog(\"warning\", \"[HMR]  - \" + moduleId);\n\t\t});\n\t}\n\n\tif (!renewedModules || renewedModules.length === 0) {\n\t\tlog(\"info\", \"[HMR] Nothing hot updated.\");\n\t} else {\n\t\tlog(\"info\", \"[HMR] Updated modules:\");\n\t\trenewedModules.forEach(function (moduleId) {\n\t\t\tif (typeof moduleId === \"string\" && moduleId.indexOf(\"!\") !== -1) {\n\t\t\t\tvar parts = moduleId.split(\"!\");\n\t\t\t\tlog.groupCollapsed(\"info\", \"[HMR]  - \" + parts.pop());\n\t\t\t\tlog(\"info\", \"[HMR]  - \" + moduleId);\n\t\t\t\tlog.groupEnd(\"info\");\n\t\t\t} else {\n\t\t\t\tlog(\"info\", \"[HMR]  - \" + moduleId);\n\t\t\t}\n\t\t});\n\t\tvar numberIds = renewedModules.every(function (moduleId) {\n\t\t\treturn typeof moduleId === \"number\";\n\t\t});\n\t\tif (numberIds)\n\t\t\tlog(\n\t\t\t\t\"info\",\n\t\t\t\t'[HMR] Consider using the optimization.moduleIds: \"named\" for module names.'\n\t\t\t);\n\t}\n};\n\n\n//# sourceURL=webpack://ssu-led-backend/./node_modules/webpack/hot/log-apply-result.js?");

/***/ }),

/***/ "./node_modules/webpack/hot/log.js":
/*!*****************************************!*\
  !*** ./node_modules/webpack/hot/log.js ***!
  \*****************************************/
/***/ ((module) => {

eval("/** @typedef {\"info\" | \"warning\" | \"error\"} LogLevel */\n\n/** @type {LogLevel} */\nvar logLevel = \"info\";\n\nfunction dummy() {}\n\n/**\n * @param {LogLevel} level log level\n * @returns {boolean} true, if should log\n */\nfunction shouldLog(level) {\n\tvar shouldLog =\n\t\t(logLevel === \"info\" && level === \"info\") ||\n\t\t([\"info\", \"warning\"].indexOf(logLevel) >= 0 && level === \"warning\") ||\n\t\t([\"info\", \"warning\", \"error\"].indexOf(logLevel) >= 0 && level === \"error\");\n\treturn shouldLog;\n}\n\n/**\n * @param {(msg?: string) => void} logFn log function\n * @returns {(level: LogLevel, msg?: string) => void} function that logs when log level is sufficient\n */\nfunction logGroup(logFn) {\n\treturn function (level, msg) {\n\t\tif (shouldLog(level)) {\n\t\t\tlogFn(msg);\n\t\t}\n\t};\n}\n\n/**\n * @param {LogLevel} level log level\n * @param {string|Error} msg message\n */\nmodule.exports = function (level, msg) {\n\tif (shouldLog(level)) {\n\t\tif (level === \"info\") {\n\t\t\tconsole.log(msg);\n\t\t} else if (level === \"warning\") {\n\t\t\tconsole.warn(msg);\n\t\t} else if (level === \"error\") {\n\t\t\tconsole.error(msg);\n\t\t}\n\t}\n};\n\nvar group = console.group || dummy;\nvar groupCollapsed = console.groupCollapsed || dummy;\nvar groupEnd = console.groupEnd || dummy;\n\nmodule.exports.group = logGroup(group);\n\nmodule.exports.groupCollapsed = logGroup(groupCollapsed);\n\nmodule.exports.groupEnd = logGroup(groupEnd);\n\n/**\n * @param {LogLevel} level log level\n */\nmodule.exports.setLogLevel = function (level) {\n\tlogLevel = level;\n};\n\n/**\n * @param {Error} err error\n * @returns {string} formatted error\n */\nmodule.exports.formatError = function (err) {\n\tvar message = err.message;\n\tvar stack = err.stack;\n\tif (!stack) {\n\t\treturn message;\n\t} else if (stack.indexOf(message) < 0) {\n\t\treturn message + \"\\n\" + stack;\n\t}\n\treturn stack;\n};\n\n\n//# sourceURL=webpack://ssu-led-backend/./node_modules/webpack/hot/log.js?");

/***/ }),

/***/ "./node_modules/webpack/hot/poll.js?100":
/*!**********************************************!*\
  !*** ./node_modules/webpack/hot/poll.js?100 ***!
  \**********************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

eval("var __resourceQuery = \"?100\";\n/*\n\tMIT License http://www.opensource.org/licenses/mit-license.php\n\tAuthor Tobias Koppers @sokra\n*/\n/* globals __resourceQuery */\nif (true) {\n\tvar hotPollInterval = +__resourceQuery.slice(1) || 0;\n\tvar log = __webpack_require__(/*! ./log */ \"./node_modules/webpack/hot/log.js\");\n\n\t/**\n\t * @param {boolean=} fromUpdate true when called from update\n\t */\n\tvar checkForUpdate = function checkForUpdate(fromUpdate) {\n\t\tif (module.hot.status() === \"idle\") {\n\t\t\tmodule.hot\n\t\t\t\t.check(true)\n\t\t\t\t.then(function (updatedModules) {\n\t\t\t\t\tif (!updatedModules) {\n\t\t\t\t\t\tif (fromUpdate) log(\"info\", \"[HMR] Update applied.\");\n\t\t\t\t\t\treturn;\n\t\t\t\t\t}\n\t\t\t\t\t__webpack_require__(/*! ./log-apply-result */ \"./node_modules/webpack/hot/log-apply-result.js\")(updatedModules, updatedModules);\n\t\t\t\t\tcheckForUpdate(true);\n\t\t\t\t})\n\t\t\t\t.catch(function (err) {\n\t\t\t\t\tvar status = module.hot.status();\n\t\t\t\t\tif ([\"abort\", \"fail\"].indexOf(status) >= 0) {\n\t\t\t\t\t\tlog(\"warning\", \"[HMR] Cannot apply update.\");\n\t\t\t\t\t\tlog(\"warning\", \"[HMR] \" + log.formatError(err));\n\t\t\t\t\t\tlog(\"warning\", \"[HMR] You need to restart the application!\");\n\t\t\t\t\t} else {\n\t\t\t\t\t\tlog(\"warning\", \"[HMR] Update failed: \" + log.formatError(err));\n\t\t\t\t\t}\n\t\t\t\t});\n\t\t}\n\t};\n\tsetInterval(checkForUpdate, hotPollInterval);\n} else {}\n\n\n//# sourceURL=webpack://ssu-led-backend/./node_modules/webpack/hot/poll.js?");

/***/ }),

/***/ "./src/app.controller.ts":
/*!*******************************!*\
  !*** ./src/app.controller.ts ***!
  \*******************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nvar __param = (this && this.__param) || function (paramIndex, decorator) {\n    return function (target, key) { decorator(target, key, paramIndex); }\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AppController = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst app_service_1 = __webpack_require__(/*! ./app.service */ \"./src/app.service.ts\");\nconst winston_1 = __webpack_require__(/*! winston */ \"winston\");\nlet AppController = class AppController {\n    constructor(appService, logger) {\n        this.appService = appService;\n        this.logger = logger;\n    }\n    getHello() {\n        this.logger.info('Called getHello()');\n        this.logger.debug('Debug message');\n        this.logger.error('Error message');\n        return this.appService.getHello();\n    }\n    healthCheck() {\n        return {\n            status: 'ok',\n            timestamp: new Date().toISOString(),\n            environment: \"development\",\n        };\n    }\n};\nexports.AppController = AppController;\n__decorate([\n    (0, common_1.Get)('logger'),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", []),\n    __metadata(\"design:returntype\", String)\n], AppController.prototype, \"getHello\", null);\n__decorate([\n    (0, common_1.Get)('health'),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", []),\n    __metadata(\"design:returntype\", void 0)\n], AppController.prototype, \"healthCheck\", null);\nexports.AppController = AppController = __decorate([\n    (0, common_1.Controller)(),\n    __param(1, (0, common_1.Inject)('winston')),\n    __metadata(\"design:paramtypes\", [app_service_1.AppService,\n        winston_1.Logger])\n], AppController);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/app.controller.ts?");

/***/ }),

/***/ "./src/app.module.ts":
/*!***************************!*\
  !*** ./src/app.module.ts ***!
  \***************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AppModule = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst app_controller_1 = __webpack_require__(/*! ./app.controller */ \"./src/app.controller.ts\");\nconst app_service_1 = __webpack_require__(/*! ./app.service */ \"./src/app.service.ts\");\nconst nest_winston_1 = __webpack_require__(/*! nest-winston */ \"nest-winston\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nconst typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ \"@nestjs/typeorm\");\nconst orm_config_1 = __webpack_require__(/*! ../config/orm.config */ \"./config/orm.config.ts\");\nconst logging_config_1 = __webpack_require__(/*! ../config/logging.config */ \"./config/logging.config.ts\");\nconst uploads_module_1 = __webpack_require__(/*! ./modules/uploads/uploads.module */ \"./src/modules/uploads/uploads.module.ts\");\nconst s3_module_1 = __webpack_require__(/*! ./modules/s3/s3.module */ \"./src/modules/s3/s3.module.ts\");\nconst auth_module_1 = __webpack_require__(/*! ./auth/auth.module */ \"./src/auth/auth.module.ts\");\nconst user_module_1 = __webpack_require__(/*! ./user/user.module */ \"./src/user/user.module.ts\");\nlet AppModule = class AppModule {\n};\nexports.AppModule = AppModule;\nexports.AppModule = AppModule = __decorate([\n    (0, common_1.Module)({\n        imports: [\n            config_1.ConfigModule.forRoot({\n                isGlobal: true,\n                envFilePath: `env/.${\"development\"}.env`,\n            }),\n            nest_winston_1.WinstonModule.forRoot(logging_config_1.winstonConfig),\n            typeorm_1.TypeOrmModule.forRootAsync({\n                imports: [config_1.ConfigModule],\n                inject: [config_1.ConfigService],\n                useFactory: (configService) => (0, orm_config_1.default)(configService),\n            }),\n            uploads_module_1.UploadsModule,\n            s3_module_1.S3Module,\n            auth_module_1.AuthModule,\n            user_module_1.UserModule,\n        ],\n        controllers: [app_controller_1.AppController],\n        providers: [app_service_1.AppService],\n    })\n], AppModule);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/app.module.ts?");

/***/ }),

/***/ "./src/app.service.ts":
/*!****************************!*\
  !*** ./src/app.service.ts ***!
  \****************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AppService = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nlet AppService = class AppService {\n    getHello() {\n        console.log(process.env.PORT);\n        return 'Hello World!';\n    }\n};\nexports.AppService = AppService;\nexports.AppService = AppService = __decorate([\n    (0, common_1.Injectable)()\n], AppService);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/app.service.ts?");

/***/ }),

/***/ "./src/auth/auth.controller.ts":
/*!*************************************!*\
  !*** ./src/auth/auth.controller.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nvar __param = (this && this.__param) || function (paramIndex, decorator) {\n    return function (target, key) { decorator(target, key, paramIndex); }\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AuthController = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst auth_service_1 = __webpack_require__(/*! ./auth.service */ \"./src/auth/auth.service.ts\");\nconst passport_1 = __webpack_require__(/*! @nestjs/passport */ \"@nestjs/passport\");\nlet AuthController = class AuthController {\n    constructor(authService) {\n        this.authService = authService;\n    }\n    async kakaoAuth() {\n        console.log('kakao login triggered');\n    }\n    async kakaoAuthCallback(req, res) {\n        const { user } = req;\n        console.log(user);\n        return this.authService.kakaoLogin(req, res);\n    }\n    async naverAuth() {\n        console.log('naver login triggered');\n    }\n    async naverAuthCallback(req, res) {\n        const { user } = req;\n        console.log(user);\n        return this.authService.naverLogin(req, res);\n    }\n};\nexports.AuthController = AuthController;\n__decorate([\n    (0, common_1.Get)('login/kakao'),\n    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('kakao')),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", []),\n    __metadata(\"design:returntype\", Promise)\n], AuthController.prototype, \"kakaoAuth\", null);\n__decorate([\n    (0, common_1.Get)('kakao/callback'),\n    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('kakao')),\n    __param(0, (0, common_1.Req)()),\n    __param(1, (0, common_1.Res)()),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", [Object, Object]),\n    __metadata(\"design:returntype\", Promise)\n], AuthController.prototype, \"kakaoAuthCallback\", null);\n__decorate([\n    (0, common_1.Get)('login/naver'),\n    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('naver')),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", []),\n    __metadata(\"design:returntype\", Promise)\n], AuthController.prototype, \"naverAuth\", null);\n__decorate([\n    (0, common_1.Get)('naver/callback'),\n    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('naver')),\n    __param(0, (0, common_1.Req)()),\n    __param(1, (0, common_1.Res)()),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", [Object, Object]),\n    __metadata(\"design:returntype\", Promise)\n], AuthController.prototype, \"naverAuthCallback\", null);\nexports.AuthController = AuthController = __decorate([\n    (0, common_1.Controller)('auth'),\n    __metadata(\"design:paramtypes\", [auth_service_1.AuthService])\n], AuthController);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/auth/auth.controller.ts?");

/***/ }),

/***/ "./src/auth/auth.module.ts":
/*!*********************************!*\
  !*** ./src/auth/auth.module.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AuthModule = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst auth_controller_1 = __webpack_require__(/*! ./auth.controller */ \"./src/auth/auth.controller.ts\");\nconst auth_service_1 = __webpack_require__(/*! ./auth.service */ \"./src/auth/auth.service.ts\");\nconst auth_entity_1 = __webpack_require__(/*! @/entities/auth.entity */ \"./src/entities/auth.entity.ts\");\nconst typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ \"@nestjs/typeorm\");\nconst user_service_1 = __webpack_require__(/*! @/user/user.service */ \"./src/user/user.service.ts\");\nconst user_entity_1 = __webpack_require__(/*! @/entities/user.entity */ \"./src/entities/user.entity.ts\");\nconst jwt_social_kakao_strategy_1 = __webpack_require__(/*! ./strategy/jwt-social-kakao.strategy */ \"./src/auth/strategy/jwt-social-kakao.strategy.ts\");\nconst passport_1 = __webpack_require__(/*! @nestjs/passport */ \"@nestjs/passport\");\nconst jwt_1 = __webpack_require__(/*! @nestjs/jwt */ \"@nestjs/jwt\");\nconst jwt_social_naver_strategy_1 = __webpack_require__(/*! ./strategy/jwt-social-naver.strategy */ \"./src/auth/strategy/jwt-social-naver.strategy.ts\");\nlet AuthModule = class AuthModule {\n};\nexports.AuthModule = AuthModule;\nexports.AuthModule = AuthModule = __decorate([\n    (0, common_1.Module)({\n        imports: [\n            typeorm_1.TypeOrmModule.forFeature([auth_entity_1.Auth, user_entity_1.User]),\n            passport_1.PassportModule,\n            jwt_1.JwtModule.register({\n                secret: process.env.JWT_ACCESS_TOKEN_SECRET,\n                signOptions: { expiresIn: '30m' },\n            }),\n        ],\n        controllers: [auth_controller_1.AuthController],\n        providers: [auth_service_1.AuthService, user_service_1.UserService, jwt_social_kakao_strategy_1.JwtKakaoStrategy, jwt_social_naver_strategy_1.JwtNaverStrategy],\n    })\n], AuthModule);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/auth/auth.module.ts?");

/***/ }),

/***/ "./src/auth/auth.service.ts":
/*!**********************************!*\
  !*** ./src/auth/auth.service.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nvar __param = (this && this.__param) || function (paramIndex, decorator) {\n    return function (target, key) { decorator(target, key, paramIndex); }\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.AuthService = void 0;\nconst auth_entity_1 = __webpack_require__(/*! @/entities/auth.entity */ \"./src/entities/auth.entity.ts\");\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ \"@nestjs/typeorm\");\nconst typeorm_2 = __webpack_require__(/*! typeorm */ \"typeorm\");\nconst user_service_1 = __webpack_require__(/*! @/user/user.service */ \"./src/user/user.service.ts\");\nconst uuid_1 = __webpack_require__(/*! uuid */ \"uuid\");\nconst jwt_1 = __webpack_require__(/*! @nestjs/jwt */ \"@nestjs/jwt\");\nlet AuthService = class AuthService {\n    constructor(authRepository, userService, jwtService) {\n        this.authRepository = authRepository;\n        this.userService = userService;\n        this.jwtService = jwtService;\n    }\n    async kakaoLogin(req, res) {\n        try {\n            const { user } = req;\n            let findUser = await this.userService.findOneBySocialId(user.socialId);\n            if (!findUser) {\n                const uuid = (0, uuid_1.v4)();\n                findUser = await this.userService.createUser(user, uuid);\n            }\n            console.log(findUser);\n            const findUserPayload = { userUuid: findUser.userUuid };\n            const access_token = await this.jwtService.sign(findUserPayload, {\n                secret: process.env.JWT_ACCESS_TOKEN_SECRET,\n                expiresIn: '30m',\n            });\n            const refresh_token = await this.jwtService.sign(findUserPayload, {\n                secret: process.env.JWT_REFRESH_TOKEN_SECRET,\n                expiresIn: '14d',\n            });\n            const userId = await this.userService.findOneById(findUser.userUuid);\n            const findAuth = await this.authRepository.create({\n                userId,\n                refreshToken: refresh_token,\n            });\n            await this.authRepository.save(findAuth);\n            const now = new Date();\n            now.setDate(now.getDate() + +'14d');\n            res.cookie('frefresh_token', refresh_token, {\n                expires: now,\n                httpOnly: true,\n            });\n            return {\n                ok: true,\n                access_token,\n            };\n        }\n        catch (error) {\n            return { ok: false, error: '구글 로그인 인증을 실패하였습니다.' };\n        }\n    }\n    async naverLogin(req, res) {\n        try {\n            const { user } = req;\n            let findUser = await this.userService.findOneBySocialId(user.socialId);\n            if (!findUser) {\n                const uuid = (0, uuid_1.v4)();\n                findUser = await this.userService.createUser(user, uuid);\n            }\n            console.log(findUser);\n            const findUserPayload = { userUuid: findUser.userUuid };\n            const access_token = await this.jwtService.sign(findUserPayload, {\n                secret: process.env.JWT_ACCESS_TOKEN_SECRET,\n                expiresIn: '30m',\n            });\n            const refresh_token = await this.jwtService.sign(findUserPayload, {\n                secret: process.env.JWT_REFRESH_TOKEN_SECRET,\n                expiresIn: '14d',\n            });\n            const userId = await this.userService.findOneById(findUser.userUuid);\n            const findAuth = await this.authRepository.create({\n                userId,\n                refreshToken: refresh_token,\n            });\n            await this.authRepository.save(findAuth);\n            const now = new Date();\n            now.setDate(now.getDate() + +'14d');\n            res.cookie('frefresh_token', refresh_token, {\n                expires: now,\n                httpOnly: true,\n            });\n            return {\n                ok: true,\n                access_token,\n            };\n        }\n        catch (error) {\n            return { ok: false, error: '구글 로그인 인증을 실패하였습니다.' };\n        }\n    }\n};\nexports.AuthService = AuthService;\nexports.AuthService = AuthService = __decorate([\n    (0, common_1.Injectable)(),\n    __param(0, (0, typeorm_1.InjectRepository)(auth_entity_1.Auth)),\n    __metadata(\"design:paramtypes\", [typeorm_2.Repository,\n        user_service_1.UserService,\n        jwt_1.JwtService])\n], AuthService);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/auth/auth.service.ts?");

/***/ }),

/***/ "./src/auth/strategy/jwt-social-kakao.strategy.ts":
/*!********************************************************!*\
  !*** ./src/auth/strategy/jwt-social-kakao.strategy.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.JwtKakaoStrategy = void 0;\nconst social_provider_enum_1 = __webpack_require__(/*! @/types/social-provider.enum */ \"./src/types/social-provider.enum.ts\");\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nconst passport_1 = __webpack_require__(/*! @nestjs/passport */ \"@nestjs/passport\");\nconst passport_kakao_1 = __webpack_require__(/*! passport-kakao */ \"passport-kakao\");\nlet JwtKakaoStrategy = class JwtKakaoStrategy extends (0, passport_1.PassportStrategy)(passport_kakao_1.Strategy, 'kakao') {\n    constructor(configService) {\n        super({\n            clientID: configService.get('KAKAO_REST_API_KEY'),\n            callbackURL: configService.get('KAKAO_REDIRECT_URL'),\n        });\n        this.configService = configService;\n    }\n    async validate(accessToken, refreshToken, profile, done) {\n        console.log(profile);\n        try {\n            console.log(profile);\n            const { id: kakaoId, _json } = profile;\n            const nickname = _json.properties?.nickname;\n            const profileImage = _json.properties?.profile_image;\n            const user = {\n                socialId: kakaoId,\n                nickname,\n                profileImage,\n                socialProvider: social_provider_enum_1.SocialProvider.KAKAO,\n            };\n            done(null, user);\n        }\n        catch (error) {\n            done(error);\n        }\n    }\n};\nexports.JwtKakaoStrategy = JwtKakaoStrategy;\nexports.JwtKakaoStrategy = JwtKakaoStrategy = __decorate([\n    (0, common_1.Injectable)(),\n    __metadata(\"design:paramtypes\", [config_1.ConfigService])\n], JwtKakaoStrategy);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/auth/strategy/jwt-social-kakao.strategy.ts?");

/***/ }),

/***/ "./src/auth/strategy/jwt-social-naver.strategy.ts":
/*!********************************************************!*\
  !*** ./src/auth/strategy/jwt-social-naver.strategy.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.JwtNaverStrategy = void 0;\nconst social_provider_enum_1 = __webpack_require__(/*! @/types/social-provider.enum */ \"./src/types/social-provider.enum.ts\");\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nconst passport_1 = __webpack_require__(/*! @nestjs/passport */ \"@nestjs/passport\");\nconst passport_naver_1 = __webpack_require__(/*! passport-naver */ \"passport-naver\");\nlet JwtNaverStrategy = class JwtNaverStrategy extends (0, passport_1.PassportStrategy)(passport_naver_1.Strategy, 'naver') {\n    constructor(configService) {\n        super({\n            clientID: configService.get('NAVER_ID'),\n            clientSecret: configService.get('NAVER_SECRET'),\n            callbackURL: configService.get('NAVER_REDIRECT_URL'),\n        });\n        this.configService = configService;\n    }\n    async validate(accessToken, refreshToken, profile, done) {\n        try {\n            console.log(profile);\n            const { id: naverId, _json } = profile;\n            const nickname = _json.nickname;\n            const profileImage = _json.profile_image;\n            const user = {\n                socialId: naverId,\n                nickname,\n                profileImage,\n                socialProvider: social_provider_enum_1.SocialProvider.NAVER,\n            };\n            done(null, user);\n        }\n        catch (error) {\n            done(error);\n        }\n    }\n};\nexports.JwtNaverStrategy = JwtNaverStrategy;\nexports.JwtNaverStrategy = JwtNaverStrategy = __decorate([\n    (0, common_1.Injectable)(),\n    __metadata(\"design:paramtypes\", [config_1.ConfigService])\n], JwtNaverStrategy);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/auth/strategy/jwt-social-naver.strategy.ts?");

/***/ }),

/***/ "./src/decorators/file-interceptor.decorator.ts":
/*!******************************************************!*\
  !*** ./src/decorators/file-interceptor.decorator.ts ***!
  \******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
eval("\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.ImageFileInterceptor = ImageFileInterceptor;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst platform_express_1 = __webpack_require__(/*! @nestjs/platform-express */ \"@nestjs/platform-express\");\nfunction ImageFileInterceptor(fieldName = 'image', maxSize = 10 * 1024 * 1024) {\n    return (0, common_1.UseInterceptors)((0, platform_express_1.FileInterceptor)(fieldName, {\n        limits: {\n            fileSize: maxSize,\n        },\n        fileFilter: (req, file, cb) => {\n            if (!file.mimetype.match(/^image\\/(jpg|jpeg|png|gif)$/)) {\n                return cb(new common_1.BadRequestException('이미지 파일만 업로드 가능합니다.'), false);\n            }\n            cb(null, true);\n        },\n    }));\n}\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/decorators/file-interceptor.decorator.ts?");

/***/ }),

/***/ "./src/decorators/swagger.decorator.ts":
/*!*********************************************!*\
  !*** ./src/decorators/swagger.decorator.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
eval("\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.ApiUploadImage = ApiUploadImage;\nexports.ApiDeleteImage = ApiDeleteImage;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst swagger_1 = __webpack_require__(/*! @nestjs/swagger */ \"@nestjs/swagger\");\nfunction ApiUploadImage() {\n    return (0, common_1.applyDecorators)((0, swagger_1.ApiOperation)({\n        summary: '이미지 업로드',\n        description: 'S3 Bucket에 이미지 파일을 업로드합니다.',\n    }), (0, swagger_1.ApiConsumes)('multipart/form-data'), (0, swagger_1.ApiBody)({\n        schema: {\n            type: 'object',\n            properties: {\n                image: {\n                    type: 'string',\n                    format: 'binary',\n                    description: '업로드할 이미지 파일 (jpg, jpeg, png, gif만 가능)',\n                },\n            },\n        },\n    }), (0, swagger_1.ApiResponse)({\n        status: 201,\n        description: '이미지가 성공적으로 업로드됨',\n        schema: {\n            type: 'object',\n            properties: {\n                imageUrl: {\n                    type: 'string',\n                    example: 'https://example-bucket.s3.amazonaws.com/images/example-image.jpg',\n                },\n                message: {\n                    type: 'string',\n                    example: '이미지가 업로드되었습니다.',\n                },\n            },\n        },\n    }), (0, swagger_1.ApiResponse)({\n        status: 400,\n        description: '잘못된 요청',\n        schema: {\n            type: 'object',\n            properties: {\n                message: {\n                    type: 'string',\n                    example: '이미지 업로드 실패: The bucket does not allow ACLs',\n                },\n                error: {\n                    type: 'string',\n                    example: 'Bad Request',\n                },\n                statusCode: {\n                    type: 'number',\n                    example: 400,\n                },\n            },\n        },\n    }));\n}\nfunction ApiDeleteImage() {\n    return (0, common_1.applyDecorators)((0, swagger_1.ApiOperation)({\n        summary: '이미지 삭제',\n        description: '업로드된 이미지를 S3에서 삭제합니다.',\n    }), (0, swagger_1.ApiParam)({\n        name: 'url',\n        description: '삭제할 이미지 URL',\n        required: true,\n    }), (0, swagger_1.ApiResponse)({\n        status: 200,\n        description: '이미지가 성공적으로 삭제됨',\n        schema: {\n            type: 'object',\n            properties: {\n                message: {\n                    type: 'string',\n                    example: '이미지가 삭제되었습니다.',\n                },\n            },\n        },\n    }), (0, swagger_1.ApiResponse)({\n        status: 400,\n        description: '잘못된 요청',\n        schema: {\n            type: 'object',\n            properties: {\n                message: {\n                    type: 'string',\n                    example: '이미지 삭제 실패: The specified key does not exist',\n                },\n                error: {\n                    type: 'string',\n                    example: 'Bad Request',\n                },\n                statusCode: {\n                    type: 'number',\n                    example: 400,\n                },\n            },\n        },\n    }));\n}\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/decorators/swagger.decorator.ts?");

/***/ }),

/***/ "./src/entities/auth.entity.ts":
/*!*************************************!*\
  !*** ./src/entities/auth.entity.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.Auth = void 0;\nconst typeorm_1 = __webpack_require__(/*! typeorm */ \"typeorm\");\nlet Auth = class Auth {\n};\nexports.Auth = Auth;\n__decorate([\n    (0, typeorm_1.PrimaryGeneratedColumn)({ name: 'id' }),\n    __metadata(\"design:type\", Number)\n], Auth.prototype, \"id\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'refresh_token', type: 'varchar', nullable: true }),\n    __metadata(\"design:type\", String)\n], Auth.prototype, \"refreshToken\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'user_id', type: 'int' }),\n    __metadata(\"design:type\", Number)\n], Auth.prototype, \"userId\", void 0);\n__decorate([\n    (0, typeorm_1.CreateDateColumn)({ name: 'created_at', type: 'timestamptz' }),\n    __metadata(\"design:type\", Date)\n], Auth.prototype, \"createdAt\", void 0);\n__decorate([\n    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at', type: 'timestamptz' }),\n    __metadata(\"design:type\", Date)\n], Auth.prototype, \"updatedAt\", void 0);\nexports.Auth = Auth = __decorate([\n    (0, typeorm_1.Entity)('auth')\n], Auth);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/entities/auth.entity.ts?");

/***/ }),

/***/ "./src/entities/user.entity.ts":
/*!*************************************!*\
  !*** ./src/entities/user.entity.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.User = void 0;\nconst social_provider_enum_1 = __webpack_require__(/*! @/types/social-provider.enum */ \"./src/types/social-provider.enum.ts\");\nconst typeorm_1 = __webpack_require__(/*! typeorm */ \"typeorm\");\nlet User = class User {\n};\nexports.User = User;\n__decorate([\n    (0, typeorm_1.PrimaryGeneratedColumn)({ name: 'id' }),\n    __metadata(\"design:type\", Number)\n], User.prototype, \"id\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'user_uuid', type: 'uuid', unique: true }),\n    __metadata(\"design:type\", String)\n], User.prototype, \"userUuid\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'nickname', type: 'varchar', unique: true }),\n    __metadata(\"design:type\", String)\n], User.prototype, \"nickname\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'profile_image', type: 'varchar', nullable: true }),\n    __metadata(\"design:type\", String)\n], User.prototype, \"profileImage\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'social_provider', type: 'enum', enum: social_provider_enum_1.SocialProvider }),\n    __metadata(\"design:type\", String)\n], User.prototype, \"socialProvider\", void 0);\n__decorate([\n    (0, typeorm_1.Column)({ name: 'social_id', type: 'varchar', nullable: true }),\n    __metadata(\"design:type\", String)\n], User.prototype, \"socialId\", void 0);\n__decorate([\n    (0, typeorm_1.CreateDateColumn)({ name: 'created_at', type: 'timestamptz' }),\n    __metadata(\"design:type\", Date)\n], User.prototype, \"createdAt\", void 0);\n__decorate([\n    (0, typeorm_1.UpdateDateColumn)({ name: 'updated_at', type: 'timestamptz' }),\n    __metadata(\"design:type\", Date)\n], User.prototype, \"updatedAt\", void 0);\nexports.User = User = __decorate([\n    (0, typeorm_1.Entity)('user')\n], User);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/entities/user.entity.ts?");

/***/ }),

/***/ "./src/main.ts":
/*!*********************!*\
  !*** ./src/main.ts ***!
  \*********************/
/***/ ((module, exports, __webpack_require__) => {

"use strict";
eval("\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nconst core_1 = __webpack_require__(/*! @nestjs/core */ \"@nestjs/core\");\nconst app_module_1 = __webpack_require__(/*! ./app.module */ \"./src/app.module.ts\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nconst nest_winston_1 = __webpack_require__(/*! nest-winston */ \"nest-winston\");\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst swagger_1 = __webpack_require__(/*! @nestjs/swagger */ \"@nestjs/swagger\");\nasync function bootstrap() {\n    const app = await core_1.NestFactory.create(app_module_1.AppModule, {\n        logger:  false\n            ? 0\n            : ['error', 'warn', 'log', 'debug', 'verbose'],\n    });\n    const configService = app.get(config_1.ConfigService);\n    app.useLogger(app.get(nest_winston_1.WINSTON_MODULE_NEST_PROVIDER));\n    app.setGlobalPrefix('api');\n    app.useGlobalPipes(new common_1.ValidationPipe({\n        whitelist: true,\n        forbidNonWhitelisted: true,\n        transform: true,\n    }));\n    app.enableCors({\n        origin:  false\n            ? 0\n            : 'http://localhost:5173',\n        credentials: true,\n    });\n    const config = new swagger_1.DocumentBuilder()\n        .setTitle('SSULED API')\n        .setDescription('SSULED API documentation')\n        .setVersion(process.env.npm_package_version || '0.0.1')\n        .addBearerAuth({\n        type: 'http',\n        scheme: 'bearer',\n        bearerFormat: 'JWT',\n        name: 'Authorization',\n        description: 'Enter JWT token',\n        in: 'header',\n    }, 'JWT-auth')\n        .build();\n    const document = swagger_1.SwaggerModule.createDocument(app, config);\n    swagger_1.SwaggerModule.setup('api/docs', app, document);\n    const port = configService.get('PORT') ?? 7777;\n    await app.listen(port);\n    console.log(`💡SSULED ${port}번 포트에서 실행중입니다.`);\n    if (true) {\n        module.hot.accept();\n        module.hot.dispose(() => app.close());\n    }\n}\nbootstrap();\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/main.ts?");

/***/ }),

/***/ "./src/modules/s3/s3.controller.ts":
/*!*****************************************!*\
  !*** ./src/modules/s3/s3.controller.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.S3Controller = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst s3_service_1 = __webpack_require__(/*! ./s3.service */ \"./src/modules/s3/s3.service.ts\");\nlet S3Controller = class S3Controller {\n    constructor(s3Service) {\n        this.s3Service = s3Service;\n    }\n};\nexports.S3Controller = S3Controller;\nexports.S3Controller = S3Controller = __decorate([\n    (0, common_1.Controller)('s3'),\n    __metadata(\"design:paramtypes\", [s3_service_1.S3Service])\n], S3Controller);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/s3/s3.controller.ts?");

/***/ }),

/***/ "./src/modules/s3/s3.module.ts":
/*!*************************************!*\
  !*** ./src/modules/s3/s3.module.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.S3Module = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst s3_service_1 = __webpack_require__(/*! ./s3.service */ \"./src/modules/s3/s3.service.ts\");\nconst s3_controller_1 = __webpack_require__(/*! ./s3.controller */ \"./src/modules/s3/s3.controller.ts\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nlet S3Module = class S3Module {\n};\nexports.S3Module = S3Module;\nexports.S3Module = S3Module = __decorate([\n    (0, common_1.Module)({\n        imports: [config_1.ConfigModule],\n        controllers: [s3_controller_1.S3Controller],\n        providers: [s3_service_1.S3Service],\n    })\n], S3Module);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/s3/s3.module.ts?");

/***/ }),

/***/ "./src/modules/s3/s3.service.ts":
/*!**************************************!*\
  !*** ./src/modules/s3/s3.service.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.S3Service = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nconst AWS = __webpack_require__(/*! aws-sdk */ \"aws-sdk\");\nconst winston_1 = __webpack_require__(/*! winston */ \"winston\");\nconst uuid_1 = __webpack_require__(/*! uuid */ \"uuid\");\nlet S3Service = class S3Service {\n    constructor(configService) {\n        this.configService = configService;\n        this.bucketName = this.configService.get('AWS_S3_BUCKET');\n        AWS.config.update({\n            accessKeyId: this.configService.get('AWS_ACCESS_KEY_ID'),\n            secretAccessKey: this.configService.get('AWS_SECRET_ACCESS_KEY'),\n            region: this.configService.get('AWS_REGION'),\n        });\n        this.s3 = new AWS.S3();\n    }\n    async uploadImage(file) {\n        try {\n            const fileExtension = file.originalname.split('.').pop();\n            const fileName = `${(0, uuid_1.v4)()}.${fileExtension}`;\n            const params = {\n                Bucket: this.bucketName,\n                Key: `images/${fileName}`,\n                Body: file.buffer,\n                ContentType: file.mimetype,\n                ACL: 'public-read',\n            };\n            const result = await this.s3.upload(params).promise();\n            this.logger.info('이미지 업로드 성공', { location: result.Location });\n            return result.Location;\n        }\n        catch (error) {\n            this.logger.error('이미지 업로드 실패', { error: error.message });\n            throw error;\n        }\n    }\n    async deleteImage(imageUrl) {\n        try {\n            const key = imageUrl.split('/').slice(3).join('/');\n            const params = {\n                Bucket: this.bucketName,\n                Key: key,\n            };\n            await this.s3.deleteObject(params).promise();\n            this.logger.info('이미지 삭제 성공', { key });\n        }\n        catch (error) {\n            this.logger.error('이미지 삭제 실패', { error: error.message });\n            throw error;\n        }\n    }\n};\nexports.S3Service = S3Service;\n__decorate([\n    (0, common_1.Inject)('winston'),\n    __metadata(\"design:type\", winston_1.Logger)\n], S3Service.prototype, \"logger\", void 0);\nexports.S3Service = S3Service = __decorate([\n    (0, common_1.Injectable)(),\n    __metadata(\"design:paramtypes\", [config_1.ConfigService])\n], S3Service);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/s3/s3.service.ts?");

/***/ }),

/***/ "./src/modules/uploads/dto/delete-image-param.dto.ts":
/*!***********************************************************!*\
  !*** ./src/modules/uploads/dto/delete-image-param.dto.ts ***!
  \***********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.DeleteImageParamDto = void 0;\nconst class_validator_1 = __webpack_require__(/*! class-validator */ \"class-validator\");\nclass DeleteImageParamDto {\n}\nexports.DeleteImageParamDto = DeleteImageParamDto;\n__decorate([\n    (0, class_validator_1.IsNotEmpty)(),\n    (0, class_validator_1.IsString)(),\n    __metadata(\"design:type\", String)\n], DeleteImageParamDto.prototype, \"ImageUrl\", void 0);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/uploads/dto/delete-image-param.dto.ts?");

/***/ }),

/***/ "./src/modules/uploads/uploads.controller.ts":
/*!***************************************************!*\
  !*** ./src/modules/uploads/uploads.controller.ts ***!
  \***************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nvar __param = (this && this.__param) || function (paramIndex, decorator) {\n    return function (target, key) { decorator(target, key, paramIndex); }\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.UploadsController = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst uploads_service_1 = __webpack_require__(/*! ./uploads.service */ \"./src/modules/uploads/uploads.service.ts\");\nconst winston_1 = __webpack_require__(/*! winston */ \"winston\");\nconst s3_service_1 = __webpack_require__(/*! ../s3/s3.service */ \"./src/modules/s3/s3.service.ts\");\nconst swagger_1 = __webpack_require__(/*! @nestjs/swagger */ \"@nestjs/swagger\");\nconst delete_image_param_dto_1 = __webpack_require__(/*! ./dto/delete-image-param.dto */ \"./src/modules/uploads/dto/delete-image-param.dto.ts\");\nconst file_interceptor_decorator_1 = __webpack_require__(/*! @/decorators/file-interceptor.decorator */ \"./src/decorators/file-interceptor.decorator.ts\");\nconst swagger_decorator_1 = __webpack_require__(/*! @/decorators/swagger.decorator */ \"./src/decorators/swagger.decorator.ts\");\nlet UploadsController = class UploadsController {\n    constructor(uploadsService, logger, s3Service) {\n        this.uploadsService = uploadsService;\n        this.logger = logger;\n        this.s3Service = s3Service;\n    }\n    async uploadImage(file) {\n        if (!file) {\n            throw new common_1.BadRequestException('이미지 파일을 제공해주세요.');\n        }\n        try {\n            this.logger.info(`이미지 업로드 시작: ${file.originalname}`);\n            const imageUrl = await this.s3Service.uploadImage(file);\n            this.logger.info(`이미지 업로드 완료: ${imageUrl}`);\n            return { message: '이미지가 업로드되었습니다.', imageUrl };\n        }\n        catch (error) {\n            this.logger.error(`이미지 업로드 실패 - ${error.message}`);\n            throw new common_1.BadRequestException(`이미지 업로드 실패: ${error.message}`);\n        }\n    }\n    async deleteImage(params) {\n        try {\n            this.logger.info(`이미지 삭제 시작: ${params.ImageUrl}`);\n            await this.s3Service.deleteImage(params.ImageUrl);\n            this.logger.info(`이미지 삭제 완료: ${params.ImageUrl}`);\n            return {\n                message: '이미지가 삭제되었습니다.',\n            };\n        }\n        catch (error) {\n            this.logger.error(`이미지 삭제 실패 - ${error.message}`);\n            throw new common_1.BadRequestException(`이미지 삭제 실패: ${error.message}`);\n        }\n    }\n};\nexports.UploadsController = UploadsController;\n__decorate([\n    (0, common_1.Post)('image'),\n    (0, swagger_decorator_1.ApiUploadImage)(),\n    (0, file_interceptor_decorator_1.ImageFileInterceptor)('image'),\n    __param(0, (0, common_1.UploadedFile)()),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", [Object]),\n    __metadata(\"design:returntype\", Promise)\n], UploadsController.prototype, \"uploadImage\", null);\n__decorate([\n    (0, common_1.Delete)('image/:url'),\n    (0, swagger_decorator_1.ApiDeleteImage)(),\n    __param(0, (0, common_1.Param)()),\n    __metadata(\"design:type\", Function),\n    __metadata(\"design:paramtypes\", [delete_image_param_dto_1.DeleteImageParamDto]),\n    __metadata(\"design:returntype\", Promise)\n], UploadsController.prototype, \"deleteImage\", null);\nexports.UploadsController = UploadsController = __decorate([\n    (0, swagger_1.ApiTags)('uploads'),\n    (0, common_1.Controller)('uploads'),\n    __param(1, (0, common_1.Inject)('winston')),\n    __metadata(\"design:paramtypes\", [uploads_service_1.UploadsService,\n        winston_1.Logger,\n        s3_service_1.S3Service])\n], UploadsController);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/uploads/uploads.controller.ts?");

/***/ }),

/***/ "./src/modules/uploads/uploads.module.ts":
/*!***********************************************!*\
  !*** ./src/modules/uploads/uploads.module.ts ***!
  \***********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.UploadsModule = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst uploads_service_1 = __webpack_require__(/*! ./uploads.service */ \"./src/modules/uploads/uploads.service.ts\");\nconst uploads_controller_1 = __webpack_require__(/*! ./uploads.controller */ \"./src/modules/uploads/uploads.controller.ts\");\nconst config_1 = __webpack_require__(/*! @nestjs/config */ \"@nestjs/config\");\nconst s3_service_1 = __webpack_require__(/*! ../s3/s3.service */ \"./src/modules/s3/s3.service.ts\");\nlet UploadsModule = class UploadsModule {\n};\nexports.UploadsModule = UploadsModule;\nexports.UploadsModule = UploadsModule = __decorate([\n    (0, common_1.Module)({\n        imports: [config_1.ConfigModule],\n        controllers: [uploads_controller_1.UploadsController],\n        providers: [uploads_service_1.UploadsService, s3_service_1.S3Service],\n    })\n], UploadsModule);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/uploads/uploads.module.ts?");

/***/ }),

/***/ "./src/modules/uploads/uploads.service.ts":
/*!************************************************!*\
  !*** ./src/modules/uploads/uploads.service.ts ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.UploadsService = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nlet UploadsService = class UploadsService {\n};\nexports.UploadsService = UploadsService;\nexports.UploadsService = UploadsService = __decorate([\n    (0, common_1.Injectable)()\n], UploadsService);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/modules/uploads/uploads.service.ts?");

/***/ }),

/***/ "./src/types/social-provider.enum.ts":
/*!*******************************************!*\
  !*** ./src/types/social-provider.enum.ts ***!
  \*******************************************/
/***/ ((__unused_webpack_module, exports) => {

"use strict";
eval("\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.SocialProvider = void 0;\nvar SocialProvider;\n(function (SocialProvider) {\n    SocialProvider[\"KAKAO\"] = \"KAKAO\";\n    SocialProvider[\"NAVER\"] = \"NAVER\";\n})(SocialProvider || (exports.SocialProvider = SocialProvider = {}));\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/types/social-provider.enum.ts?");

/***/ }),

/***/ "./src/user/user.controller.ts":
/*!*************************************!*\
  !*** ./src/user/user.controller.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.UserController = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nlet UserController = class UserController {\n};\nexports.UserController = UserController;\nexports.UserController = UserController = __decorate([\n    (0, common_1.Controller)('user')\n], UserController);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/user/user.controller.ts?");

/***/ }),

/***/ "./src/user/user.module.ts":
/*!*********************************!*\
  !*** ./src/user/user.module.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.UserModule = void 0;\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst user_controller_1 = __webpack_require__(/*! ./user.controller */ \"./src/user/user.controller.ts\");\nconst user_service_1 = __webpack_require__(/*! ./user.service */ \"./src/user/user.service.ts\");\nconst user_entity_1 = __webpack_require__(/*! @/entities/user.entity */ \"./src/entities/user.entity.ts\");\nconst typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ \"@nestjs/typeorm\");\nlet UserModule = class UserModule {\n};\nexports.UserModule = UserModule;\nexports.UserModule = UserModule = __decorate([\n    (0, common_1.Module)({\n        imports: [typeorm_1.TypeOrmModule.forFeature([user_entity_1.User])],\n        controllers: [user_controller_1.UserController],\n        providers: [user_service_1.UserService],\n    })\n], UserModule);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/user/user.module.ts?");

/***/ }),

/***/ "./src/user/user.service.ts":
/*!**********************************!*\
  !*** ./src/user/user.service.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";
eval("\nvar __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {\n    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;\n    if (typeof Reflect === \"object\" && typeof Reflect.decorate === \"function\") r = Reflect.decorate(decorators, target, key, desc);\n    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;\n    return c > 3 && r && Object.defineProperty(target, key, r), r;\n};\nvar __metadata = (this && this.__metadata) || function (k, v) {\n    if (typeof Reflect === \"object\" && typeof Reflect.metadata === \"function\") return Reflect.metadata(k, v);\n};\nvar __param = (this && this.__param) || function (paramIndex, decorator) {\n    return function (target, key) { decorator(target, key, paramIndex); }\n};\nObject.defineProperty(exports, \"__esModule\", ({ value: true }));\nexports.UserService = void 0;\nconst user_entity_1 = __webpack_require__(/*! @/entities/user.entity */ \"./src/entities/user.entity.ts\");\nconst common_1 = __webpack_require__(/*! @nestjs/common */ \"@nestjs/common\");\nconst typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ \"@nestjs/typeorm\");\nconst typeorm_2 = __webpack_require__(/*! typeorm */ \"typeorm\");\nlet UserService = class UserService {\n    constructor(repo) {\n        this.repo = repo;\n    }\n    findOneBySocialId(socialId) {\n        return this.repo.findOneBy({ socialId });\n    }\n    async findOneById(userUuid) {\n        const user = await this.repo.findOne({ where: { userUuid } });\n        if (!user) {\n            throw new Error('not found user!');\n        }\n        return user.id;\n    }\n    createUser(user, uuid) {\n        const newUser = this.repo.create({\n            userUuid: uuid,\n            nickname: user.nickname,\n            profileImage: user.profileImage,\n            socialProvider: user.socialProvider,\n            socialId: user.socialId,\n        });\n        return this.repo.save(newUser);\n    }\n};\nexports.UserService = UserService;\nexports.UserService = UserService = __decorate([\n    (0, common_1.Injectable)(),\n    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),\n    __metadata(\"design:paramtypes\", [typeorm_2.Repository])\n], UserService);\n\n\n//# sourceURL=webpack://ssu-led-backend/./src/user/user.service.ts?");

/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@nestjs/platform-express":
/*!*******************************************!*\
  !*** external "@nestjs/platform-express" ***!
  \*******************************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/platform-express");

/***/ }),

/***/ "@nestjs/swagger":
/*!**********************************!*\
  !*** external "@nestjs/swagger" ***!
  \**********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/swagger");

/***/ }),

/***/ "@nestjs/typeorm":
/*!**********************************!*\
  !*** external "@nestjs/typeorm" ***!
  \**********************************/
/***/ ((module) => {

"use strict";
module.exports = require("@nestjs/typeorm");

/***/ }),

/***/ "aws-sdk":
/*!**************************!*\
  !*** external "aws-sdk" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = require("aws-sdk");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

"use strict";
module.exports = require("class-validator");

/***/ }),

/***/ "dotenv":
/*!*************************!*\
  !*** external "dotenv" ***!
  \*************************/
/***/ ((module) => {

"use strict";
module.exports = require("dotenv");

/***/ }),

/***/ "nest-winston":
/*!*******************************!*\
  !*** external "nest-winston" ***!
  \*******************************/
/***/ ((module) => {

"use strict";
module.exports = require("nest-winston");

/***/ }),

/***/ "passport-kakao":
/*!*********************************!*\
  !*** external "passport-kakao" ***!
  \*********************************/
/***/ ((module) => {

"use strict";
module.exports = require("passport-kakao");

/***/ }),

/***/ "passport-naver":
/*!*********************************!*\
  !*** external "passport-naver" ***!
  \*********************************/
/***/ ((module) => {

"use strict";
module.exports = require("passport-naver");

/***/ }),

/***/ "typeorm":
/*!**************************!*\
  !*** external "typeorm" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = require("typeorm");

/***/ }),

/***/ "uuid":
/*!***********************!*\
  !*** external "uuid" ***!
  \***********************/
/***/ ((module) => {

"use strict";
module.exports = require("uuid");

/***/ }),

/***/ "winston":
/*!**************************!*\
  !*** external "winston" ***!
  \**************************/
/***/ ((module) => {

"use strict";
module.exports = require("winston");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			if (cachedModule.error !== undefined) throw cachedModule.error;
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		try {
/******/ 			var execOptions = { id: moduleId, module: module, factory: __webpack_modules__[moduleId], require: __webpack_require__ };
/******/ 			__webpack_require__.i.forEach(function(handler) { handler(execOptions); });
/******/ 			module = execOptions.module;
/******/ 			execOptions.factory.call(module.exports, module, module.exports, execOptions.require);
/******/ 		} catch(e) {
/******/ 			module.error = e;
/******/ 			throw e;
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = __webpack_modules__;
/******/ 	
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = __webpack_module_cache__;
/******/ 	
/******/ 	// expose the module execution interceptor
/******/ 	__webpack_require__.i = [];
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/get javascript update chunk filename */
/******/ 	(() => {
/******/ 		// This function allow to reference all chunks
/******/ 		__webpack_require__.hu = (chunkId) => {
/******/ 			// return url for filenames based on template
/******/ 			return "" + chunkId + "." + __webpack_require__.h() + ".hot-update.js";
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/get update manifest filename */
/******/ 	(() => {
/******/ 		__webpack_require__.hmrF = () => ("main." + __webpack_require__.h() + ".hot-update.json");
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/getFullHash */
/******/ 	(() => {
/******/ 		__webpack_require__.h = () => ("d1d9a65f283198a382dc")
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hot module replacement */
/******/ 	(() => {
/******/ 		var currentModuleData = {};
/******/ 		var installedModules = __webpack_require__.c;
/******/ 		
/******/ 		// module and require creation
/******/ 		var currentChildModule;
/******/ 		var currentParents = [];
/******/ 		
/******/ 		// status
/******/ 		var registeredStatusHandlers = [];
/******/ 		var currentStatus = "idle";
/******/ 		
/******/ 		// while downloading
/******/ 		var blockingPromises = 0;
/******/ 		var blockingPromisesWaiting = [];
/******/ 		
/******/ 		// The update info
/******/ 		var currentUpdateApplyHandlers;
/******/ 		var queuedInvalidatedModules;
/******/ 		
/******/ 		__webpack_require__.hmrD = currentModuleData;
/******/ 		
/******/ 		__webpack_require__.i.push(function (options) {
/******/ 			var module = options.module;
/******/ 			var require = createRequire(options.require, options.id);
/******/ 			module.hot = createModuleHotObject(options.id, module);
/******/ 			module.parents = currentParents;
/******/ 			module.children = [];
/******/ 			currentParents = [];
/******/ 			options.require = require;
/******/ 		});
/******/ 		
/******/ 		__webpack_require__.hmrC = {};
/******/ 		__webpack_require__.hmrI = {};
/******/ 		
/******/ 		function createRequire(require, moduleId) {
/******/ 			var me = installedModules[moduleId];
/******/ 			if (!me) return require;
/******/ 			var fn = function (request) {
/******/ 				if (me.hot.active) {
/******/ 					if (installedModules[request]) {
/******/ 						var parents = installedModules[request].parents;
/******/ 						if (parents.indexOf(moduleId) === -1) {
/******/ 							parents.push(moduleId);
/******/ 						}
/******/ 					} else {
/******/ 						currentParents = [moduleId];
/******/ 						currentChildModule = request;
/******/ 					}
/******/ 					if (me.children.indexOf(request) === -1) {
/******/ 						me.children.push(request);
/******/ 					}
/******/ 				} else {
/******/ 					console.warn(
/******/ 						"[HMR] unexpected require(" +
/******/ 							request +
/******/ 							") from disposed module " +
/******/ 							moduleId
/******/ 					);
/******/ 					currentParents = [];
/******/ 				}
/******/ 				return require(request);
/******/ 			};
/******/ 			var createPropertyDescriptor = function (name) {
/******/ 				return {
/******/ 					configurable: true,
/******/ 					enumerable: true,
/******/ 					get: function () {
/******/ 						return require[name];
/******/ 					},
/******/ 					set: function (value) {
/******/ 						require[name] = value;
/******/ 					}
/******/ 				};
/******/ 			};
/******/ 			for (var name in require) {
/******/ 				if (Object.prototype.hasOwnProperty.call(require, name) && name !== "e") {
/******/ 					Object.defineProperty(fn, name, createPropertyDescriptor(name));
/******/ 				}
/******/ 			}
/******/ 			fn.e = function (chunkId, fetchPriority) {
/******/ 				return trackBlockingPromise(require.e(chunkId, fetchPriority));
/******/ 			};
/******/ 			return fn;
/******/ 		}
/******/ 		
/******/ 		function createModuleHotObject(moduleId, me) {
/******/ 			var _main = currentChildModule !== moduleId;
/******/ 			var hot = {
/******/ 				// private stuff
/******/ 				_acceptedDependencies: {},
/******/ 				_acceptedErrorHandlers: {},
/******/ 				_declinedDependencies: {},
/******/ 				_selfAccepted: false,
/******/ 				_selfDeclined: false,
/******/ 				_selfInvalidated: false,
/******/ 				_disposeHandlers: [],
/******/ 				_main: _main,
/******/ 				_requireSelf: function () {
/******/ 					currentParents = me.parents.slice();
/******/ 					currentChildModule = _main ? undefined : moduleId;
/******/ 					__webpack_require__(moduleId);
/******/ 				},
/******/ 		
/******/ 				// Module API
/******/ 				active: true,
/******/ 				accept: function (dep, callback, errorHandler) {
/******/ 					if (dep === undefined) hot._selfAccepted = true;
/******/ 					else if (typeof dep === "function") hot._selfAccepted = dep;
/******/ 					else if (typeof dep === "object" && dep !== null) {
/******/ 						for (var i = 0; i < dep.length; i++) {
/******/ 							hot._acceptedDependencies[dep[i]] = callback || function () {};
/******/ 							hot._acceptedErrorHandlers[dep[i]] = errorHandler;
/******/ 						}
/******/ 					} else {
/******/ 						hot._acceptedDependencies[dep] = callback || function () {};
/******/ 						hot._acceptedErrorHandlers[dep] = errorHandler;
/******/ 					}
/******/ 				},
/******/ 				decline: function (dep) {
/******/ 					if (dep === undefined) hot._selfDeclined = true;
/******/ 					else if (typeof dep === "object" && dep !== null)
/******/ 						for (var i = 0; i < dep.length; i++)
/******/ 							hot._declinedDependencies[dep[i]] = true;
/******/ 					else hot._declinedDependencies[dep] = true;
/******/ 				},
/******/ 				dispose: function (callback) {
/******/ 					hot._disposeHandlers.push(callback);
/******/ 				},
/******/ 				addDisposeHandler: function (callback) {
/******/ 					hot._disposeHandlers.push(callback);
/******/ 				},
/******/ 				removeDisposeHandler: function (callback) {
/******/ 					var idx = hot._disposeHandlers.indexOf(callback);
/******/ 					if (idx >= 0) hot._disposeHandlers.splice(idx, 1);
/******/ 				},
/******/ 				invalidate: function () {
/******/ 					this._selfInvalidated = true;
/******/ 					switch (currentStatus) {
/******/ 						case "idle":
/******/ 							currentUpdateApplyHandlers = [];
/******/ 							Object.keys(__webpack_require__.hmrI).forEach(function (key) {
/******/ 								__webpack_require__.hmrI[key](
/******/ 									moduleId,
/******/ 									currentUpdateApplyHandlers
/******/ 								);
/******/ 							});
/******/ 							setStatus("ready");
/******/ 							break;
/******/ 						case "ready":
/******/ 							Object.keys(__webpack_require__.hmrI).forEach(function (key) {
/******/ 								__webpack_require__.hmrI[key](
/******/ 									moduleId,
/******/ 									currentUpdateApplyHandlers
/******/ 								);
/******/ 							});
/******/ 							break;
/******/ 						case "prepare":
/******/ 						case "check":
/******/ 						case "dispose":
/******/ 						case "apply":
/******/ 							(queuedInvalidatedModules = queuedInvalidatedModules || []).push(
/******/ 								moduleId
/******/ 							);
/******/ 							break;
/******/ 						default:
/******/ 							// ignore requests in error states
/******/ 							break;
/******/ 					}
/******/ 				},
/******/ 		
/******/ 				// Management API
/******/ 				check: hotCheck,
/******/ 				apply: hotApply,
/******/ 				status: function (l) {
/******/ 					if (!l) return currentStatus;
/******/ 					registeredStatusHandlers.push(l);
/******/ 				},
/******/ 				addStatusHandler: function (l) {
/******/ 					registeredStatusHandlers.push(l);
/******/ 				},
/******/ 				removeStatusHandler: function (l) {
/******/ 					var idx = registeredStatusHandlers.indexOf(l);
/******/ 					if (idx >= 0) registeredStatusHandlers.splice(idx, 1);
/******/ 				},
/******/ 		
/******/ 				// inherit from previous dispose call
/******/ 				data: currentModuleData[moduleId]
/******/ 			};
/******/ 			currentChildModule = undefined;
/******/ 			return hot;
/******/ 		}
/******/ 		
/******/ 		function setStatus(newStatus) {
/******/ 			currentStatus = newStatus;
/******/ 			var results = [];
/******/ 		
/******/ 			for (var i = 0; i < registeredStatusHandlers.length; i++)
/******/ 				results[i] = registeredStatusHandlers[i].call(null, newStatus);
/******/ 		
/******/ 			return Promise.all(results).then(function () {});
/******/ 		}
/******/ 		
/******/ 		function unblock() {
/******/ 			if (--blockingPromises === 0) {
/******/ 				setStatus("ready").then(function () {
/******/ 					if (blockingPromises === 0) {
/******/ 						var list = blockingPromisesWaiting;
/******/ 						blockingPromisesWaiting = [];
/******/ 						for (var i = 0; i < list.length; i++) {
/******/ 							list[i]();
/******/ 						}
/******/ 					}
/******/ 				});
/******/ 			}
/******/ 		}
/******/ 		
/******/ 		function trackBlockingPromise(promise) {
/******/ 			switch (currentStatus) {
/******/ 				case "ready":
/******/ 					setStatus("prepare");
/******/ 				/* fallthrough */
/******/ 				case "prepare":
/******/ 					blockingPromises++;
/******/ 					promise.then(unblock, unblock);
/******/ 					return promise;
/******/ 				default:
/******/ 					return promise;
/******/ 			}
/******/ 		}
/******/ 		
/******/ 		function waitForBlockingPromises(fn) {
/******/ 			if (blockingPromises === 0) return fn();
/******/ 			return new Promise(function (resolve) {
/******/ 				blockingPromisesWaiting.push(function () {
/******/ 					resolve(fn());
/******/ 				});
/******/ 			});
/******/ 		}
/******/ 		
/******/ 		function hotCheck(applyOnUpdate) {
/******/ 			if (currentStatus !== "idle") {
/******/ 				throw new Error("check() is only allowed in idle status");
/******/ 			}
/******/ 			return setStatus("check")
/******/ 				.then(__webpack_require__.hmrM)
/******/ 				.then(function (update) {
/******/ 					if (!update) {
/******/ 						return setStatus(applyInvalidatedModules() ? "ready" : "idle").then(
/******/ 							function () {
/******/ 								return null;
/******/ 							}
/******/ 						);
/******/ 					}
/******/ 		
/******/ 					return setStatus("prepare").then(function () {
/******/ 						var updatedModules = [];
/******/ 						currentUpdateApplyHandlers = [];
/******/ 		
/******/ 						return Promise.all(
/******/ 							Object.keys(__webpack_require__.hmrC).reduce(function (
/******/ 								promises,
/******/ 								key
/******/ 							) {
/******/ 								__webpack_require__.hmrC[key](
/******/ 									update.c,
/******/ 									update.r,
/******/ 									update.m,
/******/ 									promises,
/******/ 									currentUpdateApplyHandlers,
/******/ 									updatedModules
/******/ 								);
/******/ 								return promises;
/******/ 							}, [])
/******/ 						).then(function () {
/******/ 							return waitForBlockingPromises(function () {
/******/ 								if (applyOnUpdate) {
/******/ 									return internalApply(applyOnUpdate);
/******/ 								}
/******/ 								return setStatus("ready").then(function () {
/******/ 									return updatedModules;
/******/ 								});
/******/ 							});
/******/ 						});
/******/ 					});
/******/ 				});
/******/ 		}
/******/ 		
/******/ 		function hotApply(options) {
/******/ 			if (currentStatus !== "ready") {
/******/ 				return Promise.resolve().then(function () {
/******/ 					throw new Error(
/******/ 						"apply() is only allowed in ready status (state: " +
/******/ 							currentStatus +
/******/ 							")"
/******/ 					);
/******/ 				});
/******/ 			}
/******/ 			return internalApply(options);
/******/ 		}
/******/ 		
/******/ 		function internalApply(options) {
/******/ 			options = options || {};
/******/ 		
/******/ 			applyInvalidatedModules();
/******/ 		
/******/ 			var results = currentUpdateApplyHandlers.map(function (handler) {
/******/ 				return handler(options);
/******/ 			});
/******/ 			currentUpdateApplyHandlers = undefined;
/******/ 		
/******/ 			var errors = results
/******/ 				.map(function (r) {
/******/ 					return r.error;
/******/ 				})
/******/ 				.filter(Boolean);
/******/ 		
/******/ 			if (errors.length > 0) {
/******/ 				return setStatus("abort").then(function () {
/******/ 					throw errors[0];
/******/ 				});
/******/ 			}
/******/ 		
/******/ 			// Now in "dispose" phase
/******/ 			var disposePromise = setStatus("dispose");
/******/ 		
/******/ 			results.forEach(function (result) {
/******/ 				if (result.dispose) result.dispose();
/******/ 			});
/******/ 		
/******/ 			// Now in "apply" phase
/******/ 			var applyPromise = setStatus("apply");
/******/ 		
/******/ 			var error;
/******/ 			var reportError = function (err) {
/******/ 				if (!error) error = err;
/******/ 			};
/******/ 		
/******/ 			var outdatedModules = [];
/******/ 			results.forEach(function (result) {
/******/ 				if (result.apply) {
/******/ 					var modules = result.apply(reportError);
/******/ 					if (modules) {
/******/ 						for (var i = 0; i < modules.length; i++) {
/******/ 							outdatedModules.push(modules[i]);
/******/ 						}
/******/ 					}
/******/ 				}
/******/ 			});
/******/ 		
/******/ 			return Promise.all([disposePromise, applyPromise]).then(function () {
/******/ 				// handle errors in accept handlers and self accepted module load
/******/ 				if (error) {
/******/ 					return setStatus("fail").then(function () {
/******/ 						throw error;
/******/ 					});
/******/ 				}
/******/ 		
/******/ 				if (queuedInvalidatedModules) {
/******/ 					return internalApply(options).then(function (list) {
/******/ 						outdatedModules.forEach(function (moduleId) {
/******/ 							if (list.indexOf(moduleId) < 0) list.push(moduleId);
/******/ 						});
/******/ 						return list;
/******/ 					});
/******/ 				}
/******/ 		
/******/ 				return setStatus("idle").then(function () {
/******/ 					return outdatedModules;
/******/ 				});
/******/ 			});
/******/ 		}
/******/ 		
/******/ 		function applyInvalidatedModules() {
/******/ 			if (queuedInvalidatedModules) {
/******/ 				if (!currentUpdateApplyHandlers) currentUpdateApplyHandlers = [];
/******/ 				Object.keys(__webpack_require__.hmrI).forEach(function (key) {
/******/ 					queuedInvalidatedModules.forEach(function (moduleId) {
/******/ 						__webpack_require__.hmrI[key](
/******/ 							moduleId,
/******/ 							currentUpdateApplyHandlers
/******/ 						);
/******/ 					});
/******/ 				});
/******/ 				queuedInvalidatedModules = undefined;
/******/ 				return true;
/******/ 			}
/******/ 		}
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/require chunk loading */
/******/ 	(() => {
/******/ 		// no baseURI
/******/ 		
/******/ 		// object to store loaded chunks
/******/ 		// "1" means "loaded", otherwise not loaded yet
/******/ 		var installedChunks = __webpack_require__.hmrS_require = __webpack_require__.hmrS_require || {
/******/ 			"main": 1
/******/ 		};
/******/ 		
/******/ 		// no on chunks loaded
/******/ 		
/******/ 		// no chunk install function needed
/******/ 		
/******/ 		// no chunk loading
/******/ 		
/******/ 		// no external install chunk
/******/ 		
/******/ 		function loadUpdateChunk(chunkId, updatedModulesList) {
/******/ 			var update = require("./" + __webpack_require__.hu(chunkId));
/******/ 			var updatedModules = update.modules;
/******/ 			var runtime = update.runtime;
/******/ 			for(var moduleId in updatedModules) {
/******/ 				if(__webpack_require__.o(updatedModules, moduleId)) {
/******/ 					currentUpdate[moduleId] = updatedModules[moduleId];
/******/ 					if(updatedModulesList) updatedModulesList.push(moduleId);
/******/ 				}
/******/ 			}
/******/ 			if(runtime) currentUpdateRuntime.push(runtime);
/******/ 		}
/******/ 		
/******/ 		var currentUpdateChunks;
/******/ 		var currentUpdate;
/******/ 		var currentUpdateRemovedChunks;
/******/ 		var currentUpdateRuntime;
/******/ 		function applyHandler(options) {
/******/ 			if (__webpack_require__.f) delete __webpack_require__.f.requireHmr;
/******/ 			currentUpdateChunks = undefined;
/******/ 			function getAffectedModuleEffects(updateModuleId) {
/******/ 				var outdatedModules = [updateModuleId];
/******/ 				var outdatedDependencies = {};
/******/ 		
/******/ 				var queue = outdatedModules.map(function (id) {
/******/ 					return {
/******/ 						chain: [id],
/******/ 						id: id
/******/ 					};
/******/ 				});
/******/ 				while (queue.length > 0) {
/******/ 					var queueItem = queue.pop();
/******/ 					var moduleId = queueItem.id;
/******/ 					var chain = queueItem.chain;
/******/ 					var module = __webpack_require__.c[moduleId];
/******/ 					if (
/******/ 						!module ||
/******/ 						(module.hot._selfAccepted && !module.hot._selfInvalidated)
/******/ 					)
/******/ 						continue;
/******/ 					if (module.hot._selfDeclined) {
/******/ 						return {
/******/ 							type: "self-declined",
/******/ 							chain: chain,
/******/ 							moduleId: moduleId
/******/ 						};
/******/ 					}
/******/ 					if (module.hot._main) {
/******/ 						return {
/******/ 							type: "unaccepted",
/******/ 							chain: chain,
/******/ 							moduleId: moduleId
/******/ 						};
/******/ 					}
/******/ 					for (var i = 0; i < module.parents.length; i++) {
/******/ 						var parentId = module.parents[i];
/******/ 						var parent = __webpack_require__.c[parentId];
/******/ 						if (!parent) continue;
/******/ 						if (parent.hot._declinedDependencies[moduleId]) {
/******/ 							return {
/******/ 								type: "declined",
/******/ 								chain: chain.concat([parentId]),
/******/ 								moduleId: moduleId,
/******/ 								parentId: parentId
/******/ 							};
/******/ 						}
/******/ 						if (outdatedModules.indexOf(parentId) !== -1) continue;
/******/ 						if (parent.hot._acceptedDependencies[moduleId]) {
/******/ 							if (!outdatedDependencies[parentId])
/******/ 								outdatedDependencies[parentId] = [];
/******/ 							addAllToSet(outdatedDependencies[parentId], [moduleId]);
/******/ 							continue;
/******/ 						}
/******/ 						delete outdatedDependencies[parentId];
/******/ 						outdatedModules.push(parentId);
/******/ 						queue.push({
/******/ 							chain: chain.concat([parentId]),
/******/ 							id: parentId
/******/ 						});
/******/ 					}
/******/ 				}
/******/ 		
/******/ 				return {
/******/ 					type: "accepted",
/******/ 					moduleId: updateModuleId,
/******/ 					outdatedModules: outdatedModules,
/******/ 					outdatedDependencies: outdatedDependencies
/******/ 				};
/******/ 			}
/******/ 		
/******/ 			function addAllToSet(a, b) {
/******/ 				for (var i = 0; i < b.length; i++) {
/******/ 					var item = b[i];
/******/ 					if (a.indexOf(item) === -1) a.push(item);
/******/ 				}
/******/ 			}
/******/ 		
/******/ 			// at begin all updates modules are outdated
/******/ 			// the "outdated" status can propagate to parents if they don't accept the children
/******/ 			var outdatedDependencies = {};
/******/ 			var outdatedModules = [];
/******/ 			var appliedUpdate = {};
/******/ 		
/******/ 			var warnUnexpectedRequire = function warnUnexpectedRequire(module) {
/******/ 				console.warn(
/******/ 					"[HMR] unexpected require(" + module.id + ") to disposed module"
/******/ 				);
/******/ 			};
/******/ 		
/******/ 			for (var moduleId in currentUpdate) {
/******/ 				if (__webpack_require__.o(currentUpdate, moduleId)) {
/******/ 					var newModuleFactory = currentUpdate[moduleId];
/******/ 					/** @type {TODO} */
/******/ 					var result = newModuleFactory
/******/ 						? getAffectedModuleEffects(moduleId)
/******/ 						: {
/******/ 								type: "disposed",
/******/ 								moduleId: moduleId
/******/ 							};
/******/ 					/** @type {Error|false} */
/******/ 					var abortError = false;
/******/ 					var doApply = false;
/******/ 					var doDispose = false;
/******/ 					var chainInfo = "";
/******/ 					if (result.chain) {
/******/ 						chainInfo = "\nUpdate propagation: " + result.chain.join(" -> ");
/******/ 					}
/******/ 					switch (result.type) {
/******/ 						case "self-declined":
/******/ 							if (options.onDeclined) options.onDeclined(result);
/******/ 							if (!options.ignoreDeclined)
/******/ 								abortError = new Error(
/******/ 									"Aborted because of self decline: " +
/******/ 										result.moduleId +
/******/ 										chainInfo
/******/ 								);
/******/ 							break;
/******/ 						case "declined":
/******/ 							if (options.onDeclined) options.onDeclined(result);
/******/ 							if (!options.ignoreDeclined)
/******/ 								abortError = new Error(
/******/ 									"Aborted because of declined dependency: " +
/******/ 										result.moduleId +
/******/ 										" in " +
/******/ 										result.parentId +
/******/ 										chainInfo
/******/ 								);
/******/ 							break;
/******/ 						case "unaccepted":
/******/ 							if (options.onUnaccepted) options.onUnaccepted(result);
/******/ 							if (!options.ignoreUnaccepted)
/******/ 								abortError = new Error(
/******/ 									"Aborted because " + moduleId + " is not accepted" + chainInfo
/******/ 								);
/******/ 							break;
/******/ 						case "accepted":
/******/ 							if (options.onAccepted) options.onAccepted(result);
/******/ 							doApply = true;
/******/ 							break;
/******/ 						case "disposed":
/******/ 							if (options.onDisposed) options.onDisposed(result);
/******/ 							doDispose = true;
/******/ 							break;
/******/ 						default:
/******/ 							throw new Error("Unexception type " + result.type);
/******/ 					}
/******/ 					if (abortError) {
/******/ 						return {
/******/ 							error: abortError
/******/ 						};
/******/ 					}
/******/ 					if (doApply) {
/******/ 						appliedUpdate[moduleId] = newModuleFactory;
/******/ 						addAllToSet(outdatedModules, result.outdatedModules);
/******/ 						for (moduleId in result.outdatedDependencies) {
/******/ 							if (__webpack_require__.o(result.outdatedDependencies, moduleId)) {
/******/ 								if (!outdatedDependencies[moduleId])
/******/ 									outdatedDependencies[moduleId] = [];
/******/ 								addAllToSet(
/******/ 									outdatedDependencies[moduleId],
/******/ 									result.outdatedDependencies[moduleId]
/******/ 								);
/******/ 							}
/******/ 						}
/******/ 					}
/******/ 					if (doDispose) {
/******/ 						addAllToSet(outdatedModules, [result.moduleId]);
/******/ 						appliedUpdate[moduleId] = warnUnexpectedRequire;
/******/ 					}
/******/ 				}
/******/ 			}
/******/ 			currentUpdate = undefined;
/******/ 		
/******/ 			// Store self accepted outdated modules to require them later by the module system
/******/ 			var outdatedSelfAcceptedModules = [];
/******/ 			for (var j = 0; j < outdatedModules.length; j++) {
/******/ 				var outdatedModuleId = outdatedModules[j];
/******/ 				var module = __webpack_require__.c[outdatedModuleId];
/******/ 				if (
/******/ 					module &&
/******/ 					(module.hot._selfAccepted || module.hot._main) &&
/******/ 					// removed self-accepted modules should not be required
/******/ 					appliedUpdate[outdatedModuleId] !== warnUnexpectedRequire &&
/******/ 					// when called invalidate self-accepting is not possible
/******/ 					!module.hot._selfInvalidated
/******/ 				) {
/******/ 					outdatedSelfAcceptedModules.push({
/******/ 						module: outdatedModuleId,
/******/ 						require: module.hot._requireSelf,
/******/ 						errorHandler: module.hot._selfAccepted
/******/ 					});
/******/ 				}
/******/ 			}
/******/ 		
/******/ 			var moduleOutdatedDependencies;
/******/ 		
/******/ 			return {
/******/ 				dispose: function () {
/******/ 					currentUpdateRemovedChunks.forEach(function (chunkId) {
/******/ 						delete installedChunks[chunkId];
/******/ 					});
/******/ 					currentUpdateRemovedChunks = undefined;
/******/ 		
/******/ 					var idx;
/******/ 					var queue = outdatedModules.slice();
/******/ 					while (queue.length > 0) {
/******/ 						var moduleId = queue.pop();
/******/ 						var module = __webpack_require__.c[moduleId];
/******/ 						if (!module) continue;
/******/ 		
/******/ 						var data = {};
/******/ 		
/******/ 						// Call dispose handlers
/******/ 						var disposeHandlers = module.hot._disposeHandlers;
/******/ 						for (j = 0; j < disposeHandlers.length; j++) {
/******/ 							disposeHandlers[j].call(null, data);
/******/ 						}
/******/ 						__webpack_require__.hmrD[moduleId] = data;
/******/ 		
/******/ 						// disable module (this disables requires from this module)
/******/ 						module.hot.active = false;
/******/ 		
/******/ 						// remove module from cache
/******/ 						delete __webpack_require__.c[moduleId];
/******/ 		
/******/ 						// when disposing there is no need to call dispose handler
/******/ 						delete outdatedDependencies[moduleId];
/******/ 		
/******/ 						// remove "parents" references from all children
/******/ 						for (j = 0; j < module.children.length; j++) {
/******/ 							var child = __webpack_require__.c[module.children[j]];
/******/ 							if (!child) continue;
/******/ 							idx = child.parents.indexOf(moduleId);
/******/ 							if (idx >= 0) {
/******/ 								child.parents.splice(idx, 1);
/******/ 							}
/******/ 						}
/******/ 					}
/******/ 		
/******/ 					// remove outdated dependency from module children
/******/ 					var dependency;
/******/ 					for (var outdatedModuleId in outdatedDependencies) {
/******/ 						if (__webpack_require__.o(outdatedDependencies, outdatedModuleId)) {
/******/ 							module = __webpack_require__.c[outdatedModuleId];
/******/ 							if (module) {
/******/ 								moduleOutdatedDependencies =
/******/ 									outdatedDependencies[outdatedModuleId];
/******/ 								for (j = 0; j < moduleOutdatedDependencies.length; j++) {
/******/ 									dependency = moduleOutdatedDependencies[j];
/******/ 									idx = module.children.indexOf(dependency);
/******/ 									if (idx >= 0) module.children.splice(idx, 1);
/******/ 								}
/******/ 							}
/******/ 						}
/******/ 					}
/******/ 				},
/******/ 				apply: function (reportError) {
/******/ 					// insert new code
/******/ 					for (var updateModuleId in appliedUpdate) {
/******/ 						if (__webpack_require__.o(appliedUpdate, updateModuleId)) {
/******/ 							__webpack_require__.m[updateModuleId] = appliedUpdate[updateModuleId];
/******/ 						}
/******/ 					}
/******/ 		
/******/ 					// run new runtime modules
/******/ 					for (var i = 0; i < currentUpdateRuntime.length; i++) {
/******/ 						currentUpdateRuntime[i](__webpack_require__);
/******/ 					}
/******/ 		
/******/ 					// call accept handlers
/******/ 					for (var outdatedModuleId in outdatedDependencies) {
/******/ 						if (__webpack_require__.o(outdatedDependencies, outdatedModuleId)) {
/******/ 							var module = __webpack_require__.c[outdatedModuleId];
/******/ 							if (module) {
/******/ 								moduleOutdatedDependencies =
/******/ 									outdatedDependencies[outdatedModuleId];
/******/ 								var callbacks = [];
/******/ 								var errorHandlers = [];
/******/ 								var dependenciesForCallbacks = [];
/******/ 								for (var j = 0; j < moduleOutdatedDependencies.length; j++) {
/******/ 									var dependency = moduleOutdatedDependencies[j];
/******/ 									var acceptCallback =
/******/ 										module.hot._acceptedDependencies[dependency];
/******/ 									var errorHandler =
/******/ 										module.hot._acceptedErrorHandlers[dependency];
/******/ 									if (acceptCallback) {
/******/ 										if (callbacks.indexOf(acceptCallback) !== -1) continue;
/******/ 										callbacks.push(acceptCallback);
/******/ 										errorHandlers.push(errorHandler);
/******/ 										dependenciesForCallbacks.push(dependency);
/******/ 									}
/******/ 								}
/******/ 								for (var k = 0; k < callbacks.length; k++) {
/******/ 									try {
/******/ 										callbacks[k].call(null, moduleOutdatedDependencies);
/******/ 									} catch (err) {
/******/ 										if (typeof errorHandlers[k] === "function") {
/******/ 											try {
/******/ 												errorHandlers[k](err, {
/******/ 													moduleId: outdatedModuleId,
/******/ 													dependencyId: dependenciesForCallbacks[k]
/******/ 												});
/******/ 											} catch (err2) {
/******/ 												if (options.onErrored) {
/******/ 													options.onErrored({
/******/ 														type: "accept-error-handler-errored",
/******/ 														moduleId: outdatedModuleId,
/******/ 														dependencyId: dependenciesForCallbacks[k],
/******/ 														error: err2,
/******/ 														originalError: err
/******/ 													});
/******/ 												}
/******/ 												if (!options.ignoreErrored) {
/******/ 													reportError(err2);
/******/ 													reportError(err);
/******/ 												}
/******/ 											}
/******/ 										} else {
/******/ 											if (options.onErrored) {
/******/ 												options.onErrored({
/******/ 													type: "accept-errored",
/******/ 													moduleId: outdatedModuleId,
/******/ 													dependencyId: dependenciesForCallbacks[k],
/******/ 													error: err
/******/ 												});
/******/ 											}
/******/ 											if (!options.ignoreErrored) {
/******/ 												reportError(err);
/******/ 											}
/******/ 										}
/******/ 									}
/******/ 								}
/******/ 							}
/******/ 						}
/******/ 					}
/******/ 		
/******/ 					// Load self accepted modules
/******/ 					for (var o = 0; o < outdatedSelfAcceptedModules.length; o++) {
/******/ 						var item = outdatedSelfAcceptedModules[o];
/******/ 						var moduleId = item.module;
/******/ 						try {
/******/ 							item.require(moduleId);
/******/ 						} catch (err) {
/******/ 							if (typeof item.errorHandler === "function") {
/******/ 								try {
/******/ 									item.errorHandler(err, {
/******/ 										moduleId: moduleId,
/******/ 										module: __webpack_require__.c[moduleId]
/******/ 									});
/******/ 								} catch (err1) {
/******/ 									if (options.onErrored) {
/******/ 										options.onErrored({
/******/ 											type: "self-accept-error-handler-errored",
/******/ 											moduleId: moduleId,
/******/ 											error: err1,
/******/ 											originalError: err
/******/ 										});
/******/ 									}
/******/ 									if (!options.ignoreErrored) {
/******/ 										reportError(err1);
/******/ 										reportError(err);
/******/ 									}
/******/ 								}
/******/ 							} else {
/******/ 								if (options.onErrored) {
/******/ 									options.onErrored({
/******/ 										type: "self-accept-errored",
/******/ 										moduleId: moduleId,
/******/ 										error: err
/******/ 									});
/******/ 								}
/******/ 								if (!options.ignoreErrored) {
/******/ 									reportError(err);
/******/ 								}
/******/ 							}
/******/ 						}
/******/ 					}
/******/ 		
/******/ 					return outdatedModules;
/******/ 				}
/******/ 			};
/******/ 		}
/******/ 		__webpack_require__.hmrI.require = function (moduleId, applyHandlers) {
/******/ 			if (!currentUpdate) {
/******/ 				currentUpdate = {};
/******/ 				currentUpdateRuntime = [];
/******/ 				currentUpdateRemovedChunks = [];
/******/ 				applyHandlers.push(applyHandler);
/******/ 			}
/******/ 			if (!__webpack_require__.o(currentUpdate, moduleId)) {
/******/ 				currentUpdate[moduleId] = __webpack_require__.m[moduleId];
/******/ 			}
/******/ 		};
/******/ 		__webpack_require__.hmrC.require = function (
/******/ 			chunkIds,
/******/ 			removedChunks,
/******/ 			removedModules,
/******/ 			promises,
/******/ 			applyHandlers,
/******/ 			updatedModulesList
/******/ 		) {
/******/ 			applyHandlers.push(applyHandler);
/******/ 			currentUpdateChunks = {};
/******/ 			currentUpdateRemovedChunks = removedChunks;
/******/ 			currentUpdate = removedModules.reduce(function (obj, key) {
/******/ 				obj[key] = false;
/******/ 				return obj;
/******/ 			}, {});
/******/ 			currentUpdateRuntime = [];
/******/ 			chunkIds.forEach(function (chunkId) {
/******/ 				if (
/******/ 					__webpack_require__.o(installedChunks, chunkId) &&
/******/ 					installedChunks[chunkId] !== undefined
/******/ 				) {
/******/ 					promises.push(loadUpdateChunk(chunkId, updatedModulesList));
/******/ 					currentUpdateChunks[chunkId] = true;
/******/ 				} else {
/******/ 					currentUpdateChunks[chunkId] = false;
/******/ 				}
/******/ 			});
/******/ 			if (__webpack_require__.f) {
/******/ 				__webpack_require__.f.requireHmr = function (chunkId, promises) {
/******/ 					if (
/******/ 						currentUpdateChunks &&
/******/ 						__webpack_require__.o(currentUpdateChunks, chunkId) &&
/******/ 						!currentUpdateChunks[chunkId]
/******/ 					) {
/******/ 						promises.push(loadUpdateChunk(chunkId));
/******/ 						currentUpdateChunks[chunkId] = true;
/******/ 					}
/******/ 				};
/******/ 			}
/******/ 		};
/******/ 		
/******/ 		__webpack_require__.hmrM = function() {
/******/ 			return Promise.resolve().then(function() {
/******/ 				return require("./" + __webpack_require__.hmrF());
/******/ 			})['catch'](function(err) { if(err.code !== 'MODULE_NOT_FOUND') throw err; });
/******/ 		}
/******/ 	})();
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// module cache are used so entry inlining is disabled
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	__webpack_require__("./node_modules/webpack/hot/poll.js?100");
/******/ 	var __webpack_exports__ = __webpack_require__("./src/main.ts");
/******/ 	
/******/ })()
;