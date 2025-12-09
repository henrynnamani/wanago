import { Injectable } from '@nestjs/common';
import { SchedulerRegistry, Cron } from '@nestjs/schedule';
import { EmailService } from 'src/email/email.service';
import { EmailScheduleDto } from './dto/email-scheduling.dto';
import { CronJob } from 'cron';

@Injectable()
export class EmailSchedulingService {
  constructor(
    private readonly emailService: EmailService,
    private readonly schedulerRegistry: SchedulerRegistry,
  ) {}

  async scheduleEmail(data: EmailScheduleDto) {
    const date = new Date(data.date);

    const job = new CronJob(date, () => {
      this.emailService.sendMail({
        to: data.recipient,
        subject: data.subject,
        text: data.content,
      });
    });

    this.schedulerRegistry.addCronJob(
      `${Date.now()}-${data.subject}`,
      job as any,
    );
  }
}
