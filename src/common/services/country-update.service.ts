import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Not, IsNull } from 'typeorm';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { User } from '../../auth/entities/auth.entity';
import { UserDetails } from '../../auth/entities/user-details.entity';

@Injectable()
export class CountryUpdateService {
  private readonly logger = new Logger(CountryUpdateService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(UserDetails)
    private userDetailsRepository: Repository<UserDetails>,
    private readonly httpService: HttpService,
  ) {}

  @Cron('03 22 * * *', {
    name: 'updateCountriesFromCodes',
    timeZone: 'Africa/Nairobi',
  })
  async updateCountriesFromCodes() {
    this.logger.log('Starting country update cron job...');

    try {
      const usersWithCountryCodes = await this.userRepository
        .createQueryBuilder('user')
        .leftJoinAndSelect('user.details', 'details')
        .where('user.countryCode IS NOT NULL')
        .andWhere('user.countryCode != :empty', { empty: '' })
        .andWhere('(details.country IS NULL OR details.country = :empty)', {
          empty: '',
        })
        .getMany();

      this.logger.log(`Found ${usersWithCountryCodes.length} users to update`);

      if (usersWithCountryCodes.length === 0) {
        this.logger.log('No users need country updates');
        return;
      }

      let updatedCount = 0;
      let failedCount = 0;

      for (const user of usersWithCountryCodes) {
        try {
          const countryName = this.getCountryNameFromCode(user.countryCode);

          if (countryName) {
            await this.updateUserCountry(user.userId, countryName);
            updatedCount++;
            this.logger.debug(
              `Updated country for user ${user.userId}: ${countryName}`,
            );
          } else {
            failedCount++;
            this.logger.warn(
              `Could not find country for code: ${user.countryCode}`,
            );
          }

          // Small delay removed since we're using local mapping now
        } catch (error) {
          failedCount++;
          this.logger.error(
            `Failed to update country for user ${user.userId}:`,
            error.message,
          );
        }
      }

      this.logger.log(
        `Country update completed. Updated: ${updatedCount}, Failed: ${failedCount}`,
      );
    } catch (error) {
      this.logger.error('Error in country update cron job:', error.message);
    }
  }

  /**
   * Get country name from country calling code using local mapping
   * @param countryCode The country calling code (e.g., "254" for Kenya)
   * @returns Country name or null if not found
   */
  private getCountryNameFromCode(countryCode: string): string | null {
    try {
      // Remove any non-numeric characters and ensure it's a string
      const cleanCode = countryCode.replace(/\D/g, '');

      if (!cleanCode) {
        return null;
      }

      // Local mapping of country calling codes to country names
      const countryCodeMap: { [key: string]: string } = {
        // Africa
        '213': 'Algeria',
        '244': 'Angola',
        '229': 'Benin',
        '267': 'Botswana',
        '226': 'Burkina Faso',
        '257': 'Burundi',
        '237': 'Cameroon',
        '238': 'Cape Verde',
        '236': 'Central African Republic',
        '235': 'Chad',
        '269': 'Comoros',
        '242': 'Republic of the Congo',
        '243': 'Democratic Republic of the Congo',
        '253': 'Djibouti',
        '20': 'Egypt',
        '240': 'Equatorial Guinea',
        '291': 'Eritrea',
        '251': 'Ethiopia',
        '241': 'Gabon',
        '220': 'Gambia',
        '233': 'Ghana',
        '224': 'Guinea',
        '245': 'Guinea-Bissau',
        '225': 'Ivory Coast',
        '254': 'Kenya',
        '266': 'Lesotho',
        '231': 'Liberia',
        '218': 'Libya',
        '261': 'Madagascar',
        '265': 'Malawi',
        '223': 'Mali',
        '222': 'Mauritania',
        '230': 'Mauritius',
        '262': 'Mayotte',
        '212': 'Morocco',
        '258': 'Mozambique',
        '264': 'Namibia',
        '227': 'Niger',
        '234': 'Nigeria',
        '250': 'Rwanda',
        '239': 'Sao Tome and Principe',
        '221': 'Senegal',
        '248': 'Seychelles',
        '232': 'Sierra Leone',
        '252': 'Somalia',
        '27': 'South Africa',
        '211': 'South Sudan',
        '249': 'Sudan',
        '268': 'Eswatini',
        '255': 'Tanzania',
        '228': 'Togo',
        '216': 'Tunisia',
        '256': 'Uganda',
        '260': 'Zambia',
        '263': 'Zimbabwe',

        // Asia
        '93': 'Afghanistan',
        '880': 'Bangladesh',
        '975': 'Bhutan',
        '673': 'Brunei',
        '855': 'Cambodia',
        '86': 'China',
        '91': 'India',
        '62': 'Indonesia',
        '98': 'Iran',
        '964': 'Iraq',
        '972': 'Israel',
        '81': 'Japan',
        '962': 'Jordan',
        '7': 'Kazakhstan',
        '965': 'Kuwait',
        '996': 'Kyrgyzstan',
        '856': 'Laos',
        '961': 'Lebanon',
        '60': 'Malaysia',
        '960': 'Maldives',
        '976': 'Mongolia',
        '95': 'Myanmar',
        '977': 'Nepal',
        '850': 'North Korea',
        '968': 'Oman',
        '92': 'Pakistan',
        '970': 'Palestine',
        '63': 'Philippines',
        '974': 'Qatar',
        '966': 'Saudi Arabia',
        '65': 'Singapore',
        '82': 'South Korea',
        '94': 'Sri Lanka',
        '963': 'Syria',
        '886': 'Taiwan',
        '992': 'Tajikistan',
        '66': 'Thailand',
        '670': 'Timor-Leste',
        '90': 'Turkey',
        '993': 'Turkmenistan',
        '971': 'United Arab Emirates',
        '998': 'Uzbekistan',
        '84': 'Vietnam',
        '967': 'Yemen',

        // Europe
        '355': 'Albania',
        '376': 'Andorra',
        '43': 'Austria',
        '375': 'Belarus',
        '32': 'Belgium',
        '387': 'Bosnia and Herzegovina',
        '359': 'Bulgaria',
        '385': 'Croatia',
        '357': 'Cyprus',
        '420': 'Czech Republic',
        '45': 'Denmark',
        '372': 'Estonia',
        '358': 'Finland',
        '33': 'France',
        '995': 'Georgia',
        '49': 'Germany',
        '30': 'Greece',
        '36': 'Hungary',
        '354': 'Iceland',
        '353': 'Ireland',
        '39': 'Italy',
        '371': 'Latvia',
        '423': 'Liechtenstein',
        '370': 'Lithuania',
        '352': 'Luxembourg',
        '389': 'North Macedonia',
        '356': 'Malta',
        '373': 'Moldova',
        '377': 'Monaco',
        '382': 'Montenegro',
        '31': 'Netherlands',
        '47': 'Norway',
        '48': 'Poland',
        '351': 'Portugal',
        '40': 'Romania',
        '381': 'Serbia',
        '421': 'Slovakia',
        '386': 'Slovenia',
        '34': 'Spain',
        '46': 'Sweden',
        '41': 'Switzerland',
        '380': 'Ukraine',
        '44': 'United Kingdom',
        '379': 'Vatican City',

        // North America
        '1': 'United States',
        '52': 'Mexico',
        '1242': 'Bahamas',
        '1246': 'Barbados',
        '501': 'Belize',
        '506': 'Costa Rica',
        '53': 'Cuba',
        '1767': 'Dominica',
        '1809': 'Dominican Republic',
        '503': 'El Salvador',
        '1473': 'Grenada',
        '502': 'Guatemala',
        '509': 'Haiti',
        '504': 'Honduras',
        '1876': 'Jamaica',
        '505': 'Nicaragua',
        '507': 'Panama',
        '1787': 'Puerto Rico',
        '1869': 'Saint Kitts and Nevis',
        '1758': 'Saint Lucia',
        '1784': 'Saint Vincent and the Grenadines',
        '1868': 'Trinidad and Tobago',

        // South America
        '54': 'Argentina',
        '591': 'Bolivia',
        '55': 'Brazil',
        '56': 'Chile',
        '57': 'Colombia',
        '593': 'Ecuador',
        '594': 'French Guiana',
        '592': 'Guyana',
        '595': 'Paraguay',
        '51': 'Peru',
        '597': 'Suriname',
        '598': 'Uruguay',
        '58': 'Venezuela',

        // Oceania
        '61': 'Australia',
        '679': 'Fiji',
        '686': 'Kiribati',
        '692': 'Marshall Islands',
        '691': 'Micronesia',
        '674': 'Nauru',
        '64': 'New Zealand',
        '680': 'Palau',
        '675': 'Papua New Guinea',
        '685': 'Samoa',
        '677': 'Solomon Islands',
        '676': 'Tonga',
        '688': 'Tuvalu',
        '678': 'Vanuatu',
      };

      const country = countryCodeMap[cleanCode];
      if (country) {
        this.logger.debug(`Found country: ${country} for code: ${cleanCode}`);
        return country;
      }

      this.logger.warn(`Country code ${cleanCode} not found in local mapping`);
      return null;
    } catch (error) {
      this.logger.error(
        `Error processing country code ${countryCode}:`,
        error.message,
      );
      return null;
    }
  }

  private async updateUserCountry(
    userId: string,
    countryName: string,
  ): Promise<void> {
    try {
      let userDetails = await this.userDetailsRepository.findOne({
        where: { userId },
      });

      if (!userDetails) {
        userDetails = this.userDetailsRepository.create({
          userId,
          country: countryName,
        });
      } else {
        userDetails.country = countryName;
      }

      await this.userDetailsRepository.save(userDetails);
    } catch (error) {
      this.logger.error(
        `Failed to update country for user ${userId}:`,
        error.message,
      );
      throw error;
    }
  }

  async manualUpdateAllCountries(forceUpdate: boolean = false): Promise<{
    updated: number;
    failed: number;
    skipped: number;
    details: string[];
  }> {
    this.logger.log('Starting manual country update...');

    const queryBuilder = this.userRepository
      .createQueryBuilder('user')
      .leftJoinAndSelect('user.details', 'details')
      .where('user.countryCode IS NOT NULL')
      .andWhere('user.countryCode != :empty', { empty: '' });

    if (!forceUpdate) {
      queryBuilder.andWhere(
        '(details.country IS NULL OR details.country = :empty)',
        { empty: '' },
      );
    }

    const users = await queryBuilder.getMany();

    let updatedCount = 0;
    let failedCount = 0;
    let skippedCount = 0;
    const details: string[] = [];

    for (const user of users) {
      try {
        if (
          !forceUpdate &&
          user.details?.country &&
          user.details.country.trim() !== ''
        ) {
          skippedCount++;
          continue;
        }

        const countryName = this.getCountryNameFromCode(user.countryCode);

        if (countryName) {
          await this.updateUserCountry(user.userId, countryName);
          updatedCount++;
          details.push(
            `Updated user ${user.email}: ${user.countryCode} -> ${countryName}`,
          );
        } else {
          failedCount++;
          details.push(
            `Failed to find country for code: ${user.countryCode} (user: ${user.email})`,
          );
        }

        // Small delay removed since we're using local mapping now
      } catch (error) {
        failedCount++;
        details.push(`Error updating user ${user.email}: ${error.message}`);
      }
    }

    const result = {
      updated: updatedCount,
      failed: failedCount,
      skipped: skippedCount,
      details,
    };

    this.logger.log(`Manual country update completed:`, result);
    return result;
  }

  async getCountryMappingStats(): Promise<{
    totalUsers: number;
    usersWithCountryCode: number;
    usersWithCountry: number;
    usersNeedingUpdate: number;
    countryCodeDistribution: any[];
  }> {
    const totalUsers = await this.userRepository.count();

    const usersWithCountryCode = await this.userRepository.count({
      where: {
        countryCode: Not(IsNull()),
      },
    });

    const usersWithCountry = await this.userDetailsRepository.count({
      where: {
        country: Not(IsNull()),
      },
    });

    const usersNeedingUpdate = await this.userRepository
      .createQueryBuilder('user')
      .leftJoin('user.details', 'details')
      .where('user.countryCode IS NOT NULL')
      .andWhere('user.countryCode != :empty', { empty: '' })
      .andWhere('(details.country IS NULL OR details.country = :empty)', {
        empty: '',
      })
      .getCount();

    const countryCodeDistribution = await this.userRepository
      .createQueryBuilder('user')
      .select('user.countryCode', 'countryCode')
      .addSelect('COUNT(*)', 'count')
      .where('user.countryCode IS NOT NULL')
      .andWhere('user.countryCode != :empty', { empty: '' })
      .groupBy('user.countryCode')
      .orderBy('count', 'DESC')
      .getRawMany();

    return {
      totalUsers,
      usersWithCountryCode,
      usersWithCountry,
      usersNeedingUpdate,
      countryCodeDistribution,
    };
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
