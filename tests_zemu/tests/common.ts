import { IDeviceModel, DEFAULT_START_OPTIONS } from '@zondax/zemu'

import { resolve } from 'path'

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_X = resolve('../app/output/app_x.elf')
const APP_PATH_SP = resolve('../app/output/app_s2.elf')
const APP_PATH_ST = resolve('../app/output/app_stax.elf')
const APP_PATH_FL = resolve('../app/output/app_flex.elf')
const APP_PATH_AP = resolve('../app/output/app_apex_p.elf')

const ALL_MODELS: IDeviceModel[] = [
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
  { name: 'flex', prefix: 'FL', path: APP_PATH_FL },
  { name: 'apex_p', prefix: 'AP', path: APP_PATH_AP },
]

// ZEMU_MODELS (comma-separated model names, e.g. "nanosp") runs the suite on those models only; unset,
// every model runs, as in CI.
const SELECTED = (process.env.ZEMU_MODELS ?? '')
  .split(',')
  .map(s => s.trim())
  .filter(s => s.length > 0)
export const models: IDeviceModel[] = SELECTED.length > 0 ? ALL_MODELS.filter(m => SELECTED.includes(m.name)) : ALL_MODELS

export const PATH = "m/44'/626'/0'/0/0"

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}
