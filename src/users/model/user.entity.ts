import { Exclude } from 'class-transformer';
import {
  Column,
  Entity,
  JoinColumn,
  OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Address } from './address.entity';
import { Post } from 'src/posts/model/post.entity';
import { PublicFile } from 'src/files/model/publicfile.entity';
import { PrivateFile } from 'src/files/model/privatefile.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  @Exclude()
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  name: string;

  @Column()
  @Exclude()
  password: string;

  @OneToOne(() => Address)
  address: Address;

  @Column({ nullable: true })
  @Exclude()
  currentHashedRefreshToken?: string;

  @OneToMany(() => Post, (post) => post.author)
  posts: Post[];

  @OneToOne(() => PublicFile, { eager: true, cascade: false, nullable: true })
  @JoinColumn()
  avatar?: PublicFile;

  @OneToMany(() => PrivateFile, (file) => file.owner)
  private_files: PrivateFile[];
}
