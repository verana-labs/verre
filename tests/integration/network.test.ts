import { execSync } from 'child_process'
import { describe, it, expect, beforeAll, afterAll } from 'vitest'

// --- Constants for Docker configuration ---
const DOCKER_IMAGE_NAME = 'verana-test-node'
const DOCKER_CONTAINER_NAME = 'verana-integration-test'

describe('Integration with Verana Blockchain', () => {
  beforeAll(async () => {
    try {
      console.log('--- Setting up the test environment ---')
      console.log(`Building Docker image: ${DOCKER_IMAGE_NAME}...`)
      execSync(`docker build -f tests/integration/Dockerfile -t ${DOCKER_IMAGE_NAME} .`, { stdio: 'inherit' })

      console.log(`Starting container: ${DOCKER_CONTAINER_NAME}...`)
      execSync(`docker run -d --rm -p 1317:1317 --name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE_NAME}`, {
        stdio: 'inherit',
      })

      console.log('Waiting for the blockchain node to be ready...')
      await new Promise(resolve => setTimeout(resolve, 8000)) // 8 seconds

      console.log('Running init.sh in the container...')
      execSync(`docker exec ${DOCKER_CONTAINER_NAME} bash ./init.sh`, { stdio: 'inherit' })

      console.log('--- Environment ready ---')
    } catch (error) {
      console.error('Error during environment setup:', error)
      execSync(`docker stop ${DOCKER_CONTAINER_NAME} || true`)
      throw error
    }
  }, 120000) // Timeout of 2 minutes (120,000 ms)

  afterAll(() => {
    console.log(`--- Cleaning up test environment: stopping container ${DOCKER_CONTAINER_NAME}... ---`)
    execSync(`docker stop ${DOCKER_CONTAINER_NAME}`, { stdio: 'inherit' })
    // execSync(`docker rmi -f ${DOCKER_IMAGE_NAME} || true`, { stdio: 'inherit' })
    console.log('--- Environment clean ---')
  })

  it('should retrieve and parse the nested schema from the blockchain', async () => {
    let parsedSchema
    try {
      console.log('start')
      const response = await fetch('http://verana-integration-test:1317/cs/v1/js/1', {
        headers: { accept: 'application/json' },
      })
      console.log(response)

      if (!response.ok) {
        throw new Error(`Request failed with status ${response.status}`)
      }

      const outerObject = await response.json()

      parsedSchema = JSON.parse(outerObject.schema)
    } catch (error) {
      throw new Error(`The request failed or returned an invalid response: ${error.message}`)
    }

    expect(parsedSchema).toBeDefined()
    expect(parsedSchema).toHaveProperty('$schema')
    expect(parsedSchema.type).toBe('object')
    expect(parsedSchema.properties).toHaveProperty('credentialSubject')
  })
})
