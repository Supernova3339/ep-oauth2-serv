import SwaggerUI from 'swagger-ui-react'
import 'swagger-ui-react/swagger-ui.css'

export default function Docs() {
  return (
    <div style={{ background: '#fff', minHeight: '100vh' }}>
      <SwaggerUI
        url="/openapi.json"
        deepLinking
        displayRequestDuration
        defaultModelsExpandDepth={-1}
        tryItOutEnabled
      />
    </div>
  )
}
