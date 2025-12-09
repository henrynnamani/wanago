import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as Mail from 'nodemailer/lib/mailer';
import * as nodemailer from 'nodemailer';
import SMTPPool from 'nodemailer/lib/smtp-pool';
import { Cron, CronExpression } from '@nestjs/schedule';

@Injectable()
export class EmailService implements OnModuleInit {
  private readonly logger = new Logger(EmailService.name);
  private transporter: Mail;
  private isMailTrap: boolean = false;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit() {
    await this.initializeTransporter();
  }

  async initializeTransporter() {
    const nodeEnv = this.configService.get('NODE_ENV', 'development');

    if (nodeEnv === 'production') {
      this.initializeProductionTransporter();
    } else {
      this.initializeMailTrapTransporter();
    }

    await this.testConnection();
  }

  private initializeProductionTransporter() {
    this.isMailTrap = false;
    const service = this.configService.get('EMAIL_SERVICE');

    let emailConfiguration = {};

    if (service && service.toLowerCase() === 'gmail') {
      emailConfiguration = {
        service: 'gmail',
        auth: {
          user: this.configService.get('EMAIL_USER') as string,
          pass: this.configService.get('EMAIL_PASSWORD') as string,
        },
        from: this.configService.get('EMAIL_FROM'),
      };
    } else {
      emailConfiguration = {
        host: this.configService.get('EMAIL_HOST'),
        port: Number(this.configService.get('EMAIL_PORT', 587)),
        secure: this.configService.get('EMAIL_SECURE', 'false') === 'true',
        auth: {
          user: this.configService.get('EMAIL_USER') as string,
          pass: this.configService.get('EMAIL_PASSWORD') as string,
        },
        from: this.configService.get('EMAIL_FROM'),
      };
    }

    this.transporter = nodemailer.createTransport(emailConfiguration);
    this.logger.log(
      `Production email transporter initialized (Service: ${service || 'SMTP'})`,
    );
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      this.logger.log(
        `Email connection verified - Using ${this.isMailTrap ? 'Mailtrap' : 'Production'} service`,
      );
      return true;
    } catch (err) {
      this.logger.error(`Email connection failed`, err.message);
      return false;
    }
  }

  async sendMail(options: Mail.Options): Promise<any> {
    const from = options.from || 'noreply@gmail.com';

    const mailOptions: Mail.Options = {
      from,
      ...options,
    };

    if (this.isMailTrap) {
      mailOptions.headers = {
        ...mailOptions.headers,
        'X-Priority': '3',
        'X-Mailer': 'NestJs Mailer',
      };
    }

    try {
      const result = await this.transporter.sendMail(mailOptions);

      if (this.isMailTrap) {
        this.logger.log(
          `Email sent to MailTrap - Preview URL: https://mailtrap.io/inboxes/henrynnamani/messages/${result.messageId}`,
        );
      } else {
        this.logger.log(`Email sent successfully to ${options.to}`);
      }

      return {
        success: true,
        messageId: result.messageId,
        previewUrl: this.isMailTrap
          ? `https://mailtrap.io/inboxes/henrynnamani/messages/${result.messageId}`
          : null,
        response: result.response,
      };
    } catch (err) {
      this.logger.error('Failed to send email: ', err.message);
      throw new Error(`Email sending failed: ${err.message}`);
    }
  }

  async sendTestEmail(to: string = 'test@example.com'): Promise<any> {
    const testEmail = {
      to,
      subject: 'Test Email from NestJS with Mailtrap',
      text: `This is a test email sent from NestJS application using ${this.isMailTrap ? 'Mailtrap' : 'Production'} service.\n\nTimestamp: ${new Date().toISOString()}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px; }
            .header { background-color: #4CAF50; color: white; padding: 10px; border-radius: 5px; text-align: center; }
            .content { padding: 20px; }
            .footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Test Email</h1>
            </div>
            <div class="content">
              <p>This is a test email sent from <strong>NestJS application</strong>.</p>
              <p>Service: ${this.isMailTrap ? 'Mailtrap (Testing)' : 'Production'}</p>
              <p>Timestamp: ${new Date().toISOString()}</p>
            </div>
            <div class="footer">
              <p>This is an automated test message. Please do not reply.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    };

    return this.sendMail(testEmail);
  }

  private initializeMailTrapTransporter() {
    this.isMailTrap = true;

    const mailTrapConfig = {
      host: this.configService.get('SMTP_HOST'),
      port: this.configService.get('SMTP_PORT'),
      auth: {
        user: this.configService.get('SMTP_USERNAME') as string,
        pass: this.configService.get('SMTP_PASSWORD') as string,
      },
      secure: false,
    };

    this.transporter = nodemailer.createTransport(mailTrapConfig);
    this.logger.log(
      `Mailtrap transporter initialized for ${mailTrapConfig.host}:${mailTrapConfig.port}`,
    );
  }
}
