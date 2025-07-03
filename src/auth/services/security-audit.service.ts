import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { SecurityAuditLog } from '../entities/security-audit-log.entity';

export interface SecurityEvent {
  eventType: string;
  reason?: string;
  userId?: string;
  email?: string;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
  additionalData?: any;
  timestamp?: Date;
}

@Injectable()
export class SecurityAuditService {
  constructor(
    @InjectRepository(SecurityAuditLog)
    private auditRepository: Repository<SecurityAuditLog>,
    private config: ConfigService,
  ) {}

  async recordSecurityEvent(eventData: SecurityEvent): Promise<void> {
    try {
      const auditLog = this.auditRepository.create({
        eventType: eventData.eventType,
        reason: eventData.reason,
        userId: eventData.userId,
        email: eventData.email,
        ipAddress: eventData.ipAddress,
        userAgent: eventData.userAgent,
        sessionId: eventData.sessionId,
        additionalData: eventData.additionalData,
        timestamp: eventData.timestamp || new Date(),
      });

      await this.auditRepository.save(auditLog);
    } catch (error) {
      console.error('Failed to record security event:', error);
      throw error;
    }
  }

  async getSecurityEvents(
    userId?: string,
    limit: number = 50,
  ): Promise<SecurityAuditLog[]> {
    try {
      const queryBuilder = this.auditRepository
        .createQueryBuilder('audit')
        .leftJoinAndSelect('audit.user', 'user')
        .orderBy('audit.timestamp', 'DESC')
        .limit(limit);

      if (userId) {
        queryBuilder.where('audit.userId = :userId', { userId });
      }

      return await queryBuilder.getMany();
    } catch (error) {
      console.error('Failed to retrieve security events:', error);
      throw error;
    }
  }

  async getEventsByType(
    eventType: string,
    limit: number = 50,
  ): Promise<SecurityAuditLog[]> {
    return await this.auditRepository.find({
      where: { eventType },
      order: { timestamp: 'DESC' },
      take: limit,
      relations: ['user'],
    });
  }

  async getEventsForDateRange(
    startDate: Date,
    endDate: Date,
    userId?: string,
  ): Promise<SecurityAuditLog[]> {
    const queryBuilder = this.auditRepository
      .createQueryBuilder('audit')
      .leftJoinAndSelect('audit.user', 'user')
      .where('audit.timestamp BETWEEN :startDate AND :endDate', {
        startDate,
        endDate,
      })
      .orderBy('audit.timestamp', 'DESC');

    if (userId) {
      queryBuilder.andWhere('audit.userId = :userId', { userId });
    }

    return await queryBuilder.getMany();
  }
}
