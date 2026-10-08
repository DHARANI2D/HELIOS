"use client";

import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { Send, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { requestBillingChangeAction } from "@/app/(app)/billing/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function RequestChangeForm() {
  const [message, setMessage] = React.useState("");

  const mutation = useMutation({
    mutationFn: () => requestBillingChangeAction(message.trim()),
    onSuccess: () => {
      toast.success("Request sent to your account owner");
      setMessage("");
    },
    onError: () => toast.error("Failed to send request"),
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!message.trim()) {
          toast.error("Describe what you'd like to change");
          return;
        }
        mutation.mutate();
      }}
      className="flex gap-2"
    >
      <Input
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="e.g. Upgrade Endpoint Security to Enterprise AI tier"
        className="flex-1"
      />
      <Button type="submit" disabled={mutation.isPending}>
        {mutation.isPending ? <Loader2 className="animate-spin" /> : <Send />}
        Send
      </Button>
    </form>
  );
}
