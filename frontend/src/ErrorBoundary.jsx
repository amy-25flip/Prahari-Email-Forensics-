import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }
  static getDerivedStateFromError(error) {
    return { error }
  }
  componentDidCatch(error, info) {
    console.error('Unhandled UI error', error, info)
  }
  render() {
    if (this.state.error) {
      return <div className="app-shell"><main><div className="content">
        <div className="message error" role="alert">
          <strong>Something went wrong rendering this view.</strong>
          <p>{this.state.error.message || 'Unknown error.'}</p>
          <button className="primary" onClick={() => window.location.reload()}>Reload investigation</button>
        </div>
      </div></main></div>
    }
    return this.props.children
  }
}
