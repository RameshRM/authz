import { Namespace, Context } from "@ory/keto-namespace-types"

class User implements Namespace {}

class Team implements Namespace {
  related: {
    members: User[]
  }
}

class Resource implements Namespace {
  related: {
    parent: Resource[]
    secret_admins: (User | Team)[]
    users: (User | Team)[]
  }

  permits = {
    view_secrets: (ctx: Context): boolean =>
      this.related.secret_admins.includes(ctx.subject) ||
      this.related.secret_admins.traverse((t) => t.related.members.includes(ctx.subject)) ||
      this.related.parent.traverse((p) => p.permits.view_secrets(ctx)),

    access: (ctx: Context): boolean =>
      this.related.users.includes(ctx.subject) ||
      this.related.users.traverse((t) => t.related.members.includes(ctx.subject)) ||
      this.related.parent.traverse((p) => p.permits.access(ctx)),
  }
}
