<script setup lang="ts">
import { useHashRouter } from "@/lib/hash-router";
import { ArrowLeft } from "lucide-vue-next";
import { Sidebar } from "@/components/dashboard/sidebar";
import { ExecuteJobPanel } from "@/components/jobs/execute-job-panel";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/lib/i18n";

const { t } = useTranslation();
const router = useHashRouter();
</script>

<template>
  <div class="flex h-screen bg-background">
    <Sidebar />

    <main class="flex flex-1 flex-col overflow-hidden lg:ml-[250px]">
      <div class="h-14 shrink-0 border-b border-gray-100 bg-white px-5 py-2.5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <Button variant="ghost" size="sm" class="h-8 w-8 p-0" @click="router.back()">
              <ArrowLeft class="h-4 w-4" />
            </Button>
            <div>
              <h1 class="text-base font-semibold">{{ t.jobsPage.executeTitle }}</h1>
            </div>
          </div>
        </div>
      </div>

      <div class="flex min-h-0 flex-1 overflow-hidden p-3">
        <ExecuteJobPanel :on-cancel="() => router.back()" :on-success="() => router.push('/jobs')" />
      </div>
    </main>
  </div>
</template>
