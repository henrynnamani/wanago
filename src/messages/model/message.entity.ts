import { User } from "src/users/model/user.entity";
import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity('message')
export class Message {
    @PrimaryGeneratedColumn()
    id: string;

    @Column()
    content: string;

    @ManyToOne(() => User)
    author: User
}