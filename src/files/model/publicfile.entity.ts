import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity('files')
export class PublicFile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  key: string;

  @Column()
  url: string;
}
