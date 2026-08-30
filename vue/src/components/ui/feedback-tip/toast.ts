import { toast } from "vue-sonner";

export type FeedbackTipVariant = "success" | "error" | "info";

export function showFeedbackTip(message: string, variant: FeedbackTipVariant = "info") {
  const opts = { duration: 3000 };
  if (variant === "success") toast.success(message, opts);
  else if (variant === "error") toast.error(message, opts);
  else toast.info(message, opts);
}
