<script setup lang="ts">
import { ref } from "vue";
import { LogIn, Languages, Check } from "lucide-vue-next";
import { Button } from "@/components/ui/button";
import { FeedbackTip } from "@/components/ui/feedback-tip";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useTranslation, type Locale } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { apiRequest, formatApiError } from "@/lib/api";
import { useHashRouter, useHashSearchParams } from "@/lib/hash-router";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const { t, locale, setLocale } = useTranslation();
const router = useHashRouter();
const searchParams = useHashSearchParams();
const username = ref("");
const password = ref("");
const error = ref("");
const errorId = ref(0);
const isLoading = ref(false);

const handleSubmit = async () => {
  error.value = "";

  if (!username.value || !password.value) {
    error.value = t.value.login.errorRequired;
    errorId.value += 1;
    return;
  }

  isLoading.value = true;

  try {
    const form = new URLSearchParams();
    form.set("name", username.value);
    form.set("password", password.value);

    await apiRequest("/api/v1/user/login", {
      method: "POST",
      body: form,
      errorMessage: t.value.login.errorInvalid,
    });
    const next = searchParams.value.get("next") || "/";
    router.replace(next);
    router.refresh();
  } catch (err) {
    error.value = formatApiError(err, t.value.login.errorInvalid);
    errorId.value += 1;
  } finally {
    isLoading.value = false;
  }
};
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-gradient-to-br from-background to-muted/50">
    <div class="flex w-full max-w-6xl">
      <!-- Left side - Login Form -->
      <div class="flex w-full flex-col justify-center px-8 py-12 sm:w-1/2 sm:px-12 lg:px-16 relative">
        <!-- Language Switcher -->
        <div class="absolute top-4 right-4">
          <DropdownMenu>
            <DropdownMenuTrigger as-child>
              <Button variant="outline" size="icon" class="h-9 w-9">
                <Languages class="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                class="flex items-center justify-between"
                @click="setLocale('zh' as Locale)"
              >
                <span>ZH</span>
                <Check v-if="locale === 'zh'" class="h-4 w-4 ml-2" />
              </DropdownMenuItem>
              <DropdownMenuItem
                class="flex items-center justify-between"
                @click="setLocale('en' as Locale)"
              >
                <span>EN</span>
                <Check v-if="locale === 'en'" class="h-4 w-4 ml-2" />
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        <!-- Logo/Title -->
        <div class="mb-8">
          <div class="flex items-center gap-2 text-2xl font-bold">
            <div class="flex items-center justify-center rounded-lg bg-primary p-1.5 text-primary-foreground">
              <LogIn class="h-5 w-5" />
            </div>
            <span>Pigeon Console</span>
          </div>
        </div>

        <!-- Form Header -->
        <div class="mb-8">
          <h1 class="mb-2 text-3xl font-bold tracking-tight text-foreground">{{ t.login.title }}</h1>
          <p class="text-sm text-muted-foreground">{{ t.login.subtitle }}</p>
        </div>

        <!-- Error Message -->
        <FeedbackTip
          v-if="error"
          :key="errorId"
          :message="error"
          variant="error"
          :compact="false"
          class="mb-4"
        />

        <!-- Login Form -->
        <form class="space-y-4" @submit.prevent="handleSubmit">
          <!-- Username Field -->
          <div class="space-y-1.5">
            <Label for="username" class="text-sm font-medium">
              {{ t.login.username }}
            </Label>
            <Input
              id="username"
              type="text"
              :placeholder="t.login.usernamePlaceholder"
              v-model="username"
              :disabled="isLoading"
              autocomplete="username"
            />
          </div>

          <!-- Password Field -->
          <div class="space-y-1.5">
            <Label for="password" class="text-sm font-medium">
              {{ t.login.password }}
            </Label>
            <Input
              id="password"
              type="password"
              :placeholder="t.login.passwordPlaceholder"
              v-model="password"
              :disabled="isLoading"
              autocomplete="current-password"
            />
          </div>

          <!-- Submit Button -->
          <Button
            type="submit"
            :disabled="isLoading"
            :class="cn('w-full', isLoading && 'opacity-50')"
            size="lg"
          >
            {{ isLoading ? t.common.loading : t.login.signIn }}
          </Button>
        </form>

        <!-- Footer -->
        <div class="mt-8 text-center text-xs text-muted-foreground">
          <p>&copy; 2024 - present, firerpa.</p>
        </div>
      </div>

      <!-- Right side - Decorative Background -->
      <div class="hidden w-1/2 bg-gradient-to-br from-primary/10 via-background to-primary/5 sm:block">
        <div class="flex h-full items-center justify-center p-12">
          <div class="space-y-8 text-center">
            <div class="inline-block rounded-lg bg-primary/10 p-8">
              <div class="h-24 w-24 rounded-lg bg-gradient-to-br from-primary to-primary/50 opacity-50" />
            </div>
            <div class="space-y-3">
              <h2 class="text-2xl font-bold text-foreground">Welcome</h2>
              <p class="text-sm text-muted-foreground">
                Unified management for distributed nodes and autonomous task scheduling
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
