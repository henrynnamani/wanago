import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { EmailScheduleDto } from './dto/email-scheduling.dto';
import { EmailSchedulingService } from './email-scheduling.service';
import { JwtAuthGuard } from 'src/auths/guard/jwt.guard';

@Controller('email-scheduling')
export class EmailSchedulingController {
  constructor(
    private readonly emailSchedulingService: EmailSchedulingService,
  ) {}

  @Post('schedule')
  @UseGuards(JwtAuthGuard)
  async scheduleEmail(@Body() emailScheduleData: EmailScheduleDto) {
    return this.emailSchedulingService.scheduleEmail(emailScheduleData);
  }
}
