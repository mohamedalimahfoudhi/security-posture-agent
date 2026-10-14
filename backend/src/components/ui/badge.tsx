import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-muted text-foreground",
        outline: "border-border text-foreground",
        critical:
          "border-critical/30 bg-critical/10 text-critical",
        high: "border-orange-500/30 bg-orange-500/10 text-orange-400",
        medium: "border-warning/30 bg-warning/10 text-warning",
        low: "border-primary/30 bg-primary/10 text-blue-400",
        success: "border-success/30 bg-success/10 text-success",
        open: "border-critical/30 bg-critical/10 text-critical",
        investigating: "border-warning/30 bg-warning/10 text-warning",
        resolved: "border-success/30 bg-success/10 text-success",
        closed: "border-muted-foreground/30 bg-muted/50 text-muted-foreground",
        atRisk: "border-critical/30 bg-critical/10 text-critical",
        monitoring: "border-warning/30 bg-warning/10 text-warning",
        healthy: "border-success/30 bg-success/10 text-success",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
