import { MiddlewareConsumer, Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { WinstonModule } from 'nest-winston';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import typeOrmConfig from '../config/orm.config';
import { winstonConfig } from '../config/logging.config';
import { UploadsModule } from './modules/uploads/uploads.module';
import { S3Module } from './modules/s3/s3.module';
import { AuthModule } from './auth/auth.module';
import { PostsModule } from './modules/posts/posts.module';
import { HttpLoggerMiddleware } from './middlewares/http-logger.middleware';
import { CommentsModule } from './modules/comments/comments.module';
import { LikesModule } from './modules/likes/likes.module';
import { UsersModule } from './modules/users/users.module';
import { GroupModule } from './modules/group/group.module';
import { StatisticsModule } from './modules/statistics/statistics.module';
import { addTransactionalDataSource } from 'typeorm-transactional';
import { DataSource } from 'typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: `env/.${process.env.NODE_ENV || 'development'}.env`,
      isGlobal: true,
    }),
    WinstonModule.forRoot(winstonConfig),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) =>
        typeOrmConfig(configService),
      async dataSourceFactory(option) {
        if (!option) throw new Error('Invalid options passed');

        return addTransactionalDataSource(new DataSource(option));
      },
    }),
    UploadsModule,
    S3Module,
    AuthModule,
    PostsModule,
    CommentsModule,
    LikesModule,
    UsersModule,
    GroupModule,
    StatisticsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(HttpLoggerMiddleware).forRoutes('*');
  }
}
