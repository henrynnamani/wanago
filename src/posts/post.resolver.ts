import { Query, Resolver } from "@nestjs/graphql";
import { Post } from "./model/post.model";
import { PostsService } from "./posts.service";

@Resolver(() => Post)
export class PostsResolver {
    constructor(
        private readonly postsService: PostsService
    ) {}

    @Query(() => [Post])
    async posts() {
        const posts = await this.postsService.getAllPosts();
        return posts;
    }
}