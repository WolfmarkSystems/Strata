import { invoke } from '@tauri-apps/api/core'

export async function getAppVersion(): Promise<string> {
  try {
    return await invoke('get_app_version')
  } catch {
    return '0.3.0'
  }
}

export async function checkLicense(): Promise<{ status: string; days: number }> {
  try {
    return await invoke('check_license')
  } catch {
    return { status: 'dev', days: 999 }
  }
}

export async function getExaminerProfile(): Promise<{
  name: string
  agency: string
  badge: string
}> {
  try {
    return await invoke('get_examiner_profile')
  } catch {
    return {
      name: 'Dev Examiner',
      agency: 'Wolfmark Systems',
      badge: 'DEV-001',
    }
  }
}
