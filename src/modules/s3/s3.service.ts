import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as AWS from 'aws-sdk';
import { Logger } from 'winston';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class S3Service {
  private readonly s3: AWS.S3;
  @Inject('winston')
  private readonly logger: Logger;
  private readonly bucketName: string;

  constructor(private readonly configService: ConfigService) {
    this.bucketName = this.configService.get<string>('AWS_S3_BUCKET');

    AWS.config.update({
      accessKeyId: this.configService.get<string>('AWS_ACCESS_KEY_ID'),
      secretAccessKey: this.configService.get<string>('AWS_SECRET_ACCESS_KEY'),
      region: this.configService.get<string>('AWS_REGION'),
    });

    this.s3 = new AWS.S3();
  }

  async uploadImage(file: Express.Multer.File): Promise<string> {
    try {
      const fileExtension = file.originalname.split('.').pop();
      const fileName = `${uuidv4()}.${fileExtension}`;

      const params = {
        Bucket: this.bucketName,
        Key: `images/${fileName}`,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'public-read',
      };

      const result = await this.s3.upload(params).promise();
      this.logger.info('이미지 업로드 성공', { location: result.Location });
      return result.Location;
    } catch (error) {
      this.logger.error('이미지 업로드 실패', { error: error.message });
      throw error;
    }
  }

  async deleteImage(imageUrl: string): Promise<void> {
    try {
      const key = imageUrl.split('/').slice(3).join('/');

      const params = {
        Bucket: this.bucketName,
        Key: key,
      };

      await this.s3.deleteObject(params).promise();
      this.logger.info('이미지 삭제 성공', { key });
    } catch (error) {
      this.logger.error('이미지 삭제 실패', { error: error.message });
      throw error;
    }
  }
}
