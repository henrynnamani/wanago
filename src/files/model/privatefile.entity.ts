import { User } from 'src/users/model/user.entity';
import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';

@Entity('private_files')
export class PrivateFile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  key: string;

  @ManyToOne(() => User, (owner) => owner.private_files)
  owner: User;
}
